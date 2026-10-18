package witness

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
func KeyFromStatement(raw []byte, revokedAt int64, roots statement.RootKey, kid string, at, seen time.Time) ([]byte, error) {
	st, err := statement.Verify(raw, roots)
	if err != nil {
		return nil, fmt.Errorf("the statement for %s does not verify: %w", kid, err)
	}
	if st.Kid != kid || st.JWK.Alg != string(policy.ES256) {
		return nil, fmt.Errorf("no statement certifies %s as an ES256 key", kid)
	}
	if !st.ValidAt(at) {
		return nil, fmt.Errorf("the statement does not certify %s at %s", kid, at.UTC().Format(time.RFC3339))
	}
	if revokedAt != 0 && seen.Unix() >= revokedAt {
		return nil, fmt.Errorf("%s was revoked before the record was seen", kid)
	}
	b, _ := json.Marshal(st.JWK)
	_, pub, err := statement.ParseJWK(b, policy.ES256)
	return pub, err
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
	rootsAt time.Time
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
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK || len(b) > maxAnswer {
		return nil, fmt.Errorf("custody answered %d for %s", resp.StatusCode, path)
	}
	return b, nil
}

// Key implements Keys.
func (c *CustodyKeys) Key(kid string, at, seen time.Time) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ttl := c.TTL
	if ttl == 0 {
		ttl = time.Minute
	}
	if c.roots == nil || seen.Sub(c.rootsAt) > 5*ttl || seen.Before(c.rootsAt) {
		raw, err := c.get("/v1/jwks/" + statement.RootName)
		if err != nil {
			return nil, fmt.Errorf("the delegation root's key set: %w", err)
		}
		roots, err := statement.KeysFromJWKS(raw)
		if err != nil {
			return nil, err
		}
		c.roots, c.rootsAt = roots, seen
	}
	if c.answers == nil {
		c.answers = map[string]cached{}
	}
	a, ok := c.answers[kid]
	if !ok || seen.Sub(a.at) > ttl || seen.Before(a.at) {
		raw, err := c.get("/v1/statements/" + url.PathEscape(kid))
		if err != nil {
			return nil, fmt.Errorf("no statement certifies %s: %w", kid, err)
		}
		st, revoked, err := ParseStatementAnswer(raw)
		if err != nil {
			return nil, err
		}
		a = cached{raw: st, revoked: revoked, at: seen}
		c.answers[kid] = a
	}
	return KeyFromStatement(a.raw, a.revoked, c.roots, kid, at, seen)
}
