package witness

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/policy"
	"github.com/TAIPANBOX/keyryx/internal/statement"
)

// KeyFromStatement is the key a checkpoint's kid names, if a key statement
// certifies it: the statement verifies under both halves of the delegation
// root, certifies that kid as an ES256 key, is valid at the record's time,
// and was not revoked by the time the record was seen (SPEC 6.5.1 step 2).
// seen is the witness's own clock, never the record's: a record backdated
// into a revoked key's life is refused, while one whose short-lived key has
// merely expired since is not.
func KeyFromStatement(raw []byte, revokedAt int64, roots statement.RootKey, kid string, at, seen time.Time) (Certified, error) {
	st, err := statement.Verify(raw, roots)
	if err != nil {
		return Certified{}, fmt.Errorf("the statement for %s does not verify: %w", kid, err)
	}
	if st.Kid != kid || st.JWK.Alg != string(policy.ES256) {
		return Certified{}, fmt.Errorf("no statement certifies %s as an ES256 key", kid)
	}
	if !st.ValidAt(at) {
		return Certified{}, fmt.Errorf("the statement does not certify %s at %s", kid, at.UTC().Format(time.RFC3339))
	}
	if revokedAt != 0 && seen.Unix() >= revokedAt {
		return Certified{}, fmt.Errorf("%s was revoked before the record was seen", kid)
	}
	b, _ := json.Marshal(st.JWK)
	_, pub, err := statement.ParseJWK(b, policy.ES256)
	return Certified{Public: pub, Name: st.Name, Owner: st.Owner}, err
}

// ErrUnavailable is custody not answering, or answering 5xx: the record
// waits, since nothing about it was refused.
var ErrUnavailable = errors.New("custody is unreachable")

// streamRe and keyNameRe are the two halves of a stream-to-key binding.
var (
	streamRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,250}\.ndjson$`)
	keyNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// ParseStreamKeys reads `stream|key-name` bindings, comma or line separated:
// the delegated key name each stream's checkpoint key is certified under.
func ParseStreamKeys(spec string) (map[string]string, error) {
	out := map[string]string{}
	for _, item := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == '\n' }) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		stream, key, ok := strings.Cut(item, "|")
		if !ok || !streamRe.MatchString(stream) || !keyNameRe.MatchString(key) {
			return nil, fmt.Errorf("%q is not stream.ndjson|key-name", item)
		}
		if _, dup := out[stream]; dup {
			return nil, fmt.Errorf("stream %s is bound to two keys", stream)
		}
		out[stream] = key
	}
	return out, nil
}

// CheckBound refuses a certified key that is not the one bound to stream: a
// checkpoint is its producer's word, so another producer's key, however
// valid, does not sign it.
func CheckBound(bound map[string]string, stream string, c Certified) error {
	want, ok := bound[stream]
	if !ok {
		return fmt.Errorf("no key is bound to %s, so no signature on its checkpoints is its producer's", stream)
	}
	if c.Name != want {
		return fmt.Errorf("the key is certified for %s, and %s is bound to %s", c.Name, stream, want)
	}
	return nil
}

// RootKids is the set of kids custody serves for the delegation root now,
// sorted, so the witness can compare it with the set it pinned.
func (c *CustodyKeys) RootKids(seen time.Time) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.refreshRoots(seen); err != nil {
		return nil, err
	}
	return append([]string(nil), c.served...), nil
}

// Pin sets the root kids the client trusts: a statement verifies only under
// those, whatever else is served beside them.
func (c *CustodyKeys) Pin(kids []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pin = map[string]bool{}
	for _, k := range kids {
		c.pin[k] = true
	}
}

// statementAnswer is GET /v1/statements/{kid}.
type statementAnswer struct {
	Statement json.RawMessage `json:"statement"`
	RevokedAt int64           `json:"revoked_at"`
}

// ParseStatementAnswer reads custody's statement answer, as served and as an
// auditor saves it.
func ParseStatementAnswer(raw []byte) ([]byte, int64, error) {
	var a statementAnswer
	if err := json.Unmarshal(raw, &a); err != nil || len(a.Statement) == 0 || a.RevokedAt < 0 {
		return nil, 0, errors.New("not a statement answer")
	}
	return a.Statement, a.RevokedAt, nil
}

// CustodyKeys asks custody for the statement of each kid and for the
// delegation root's key set, and keeps both for a short while.
type CustodyKeys struct {
	Base string
	HTTP *http.Client
	TTL  time.Duration

	mu      sync.Mutex
	roots   statement.RootKey
	served  []string
	rootsAt time.Time
	pin     map[string]bool
	answers map[string]cached
}

type cached struct {
	raw     []byte
	revoked int64
	at      time.Time
}

const maxAnswer = 1 << 20

func (c *CustodyKeys) get(path string) ([]byte, error) {
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Get(strings.TrimRight(c.Base, "/") + path) // #nosec G107 -- the operator's configured custody URL
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("%w: custody answered %d for %s", ErrUnavailable, resp.StatusCode, path)
	}
	if resp.StatusCode != http.StatusOK || len(b) > maxAnswer {
		return nil, fmt.Errorf("custody answered %d for %s", resp.StatusCode, path)
	}
	return b, nil
}

func (c *CustodyKeys) ttl() time.Duration {
	if c.TTL == 0 {
		return time.Minute
	}
	return c.TTL
}

// refreshRoots reads the delegation root's key set when the copy held is
// older than five intervals, and records the kids it serves.
func (c *CustodyKeys) refreshRoots(seen time.Time) error {
	if c.roots != nil && seen.Sub(c.rootsAt) <= 5*c.ttl() && !seen.Before(c.rootsAt) {
		return nil
	}
	raw, err := c.get("/v1/jwks/" + statement.RootName)
	if err != nil {
		return fmt.Errorf("the delegation root's key set: %w", err)
	}
	roots, err := statement.KeysFromJWKS(raw)
	if err != nil {
		return err
	}
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	_ = json.Unmarshal(raw, &set)
	served := []string{}
	for _, k := range set.Keys {
		if _, _, ok := roots(k.Kid); ok {
			served = append(served, k.Kid)
		}
	}
	sort.Strings(served)
	c.roots, c.served, c.rootsAt = roots, served, seen
	return nil
}

// Key implements Keys: the statement for kid, verified only under the root
// kids the witness pinned.
func (c *CustodyKeys) Key(kid string, at, seen time.Time) (Certified, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pin == nil {
		return Certified{}, errors.New("no delegation root is pinned, so no statement can be checked")
	}
	if err := c.refreshRoots(seen); err != nil {
		return Certified{}, err
	}
	roots, pin := c.roots, c.pin
	pinned := func(k string) (policy.Alg, []byte, bool) {
		if !pin[k] {
			return "", nil, false
		}
		return roots(k)
	}
	if c.answers == nil {
		c.answers = map[string]cached{}
	}
	a, ok := c.answers[kid]
	if !ok || seen.Sub(a.at) > c.ttl() || seen.Before(a.at) {
		raw, err := c.get("/v1/statements/" + url.PathEscape(kid))
		if err != nil {
			return Certified{}, fmt.Errorf("no statement certifies %s: %w", kid, err)
		}
		st, revoked, err := ParseStatementAnswer(raw)
		if err != nil {
			return Certified{}, err
		}
		a = cached{raw: st, revoked: revoked, at: seen}
		c.answers[kid] = a
	}
	return KeyFromStatement(a.raw, a.revoked, pinned, kid, at, seen)
}
