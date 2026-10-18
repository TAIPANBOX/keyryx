// Package certify issues key statements for delegated keys (CLAUDE.md
// invariants 24 to 29).
//
// A consumer that signs at a high rate (the delegation service's tokens, a
// producer's stream checkpoints) generates its own key and keeps it in
// memory. To have it certified it asks for a challenge, signs the challenge
// with that key (a proof of possession, so nobody can have certified a key
// they do not hold), and gets back a statement both halves of the delegation
// root signed: this key is that consumer's, for that name, from not_before to
// not_after. Custody never sees the private key.
//
// # Life of a delegated key
//
// A statement's life is at most the name's max_lifetime and at least ten
// minutes. The key is published in the name's key set from the moment it is
// certified until its not_after plus the name's overlap, so a token it signed
// just before not_after keeps verifying for as long as such a token lives.
// A renewal, asked while another key of the name is still valid a
// publish-ahead time from now, starts that publish-ahead time later, so
// verifiers that cache the key set hold the new key before it signs anything;
// a first key, or a late renewal with nothing valid then, may sign at once.
// A key id is certified once. A revoked key leaves the key set at once and is
// never certified again, and a statement whose root key was revoked is no
// longer published.
package certify

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/policy"
	"github.com/TAIPANBOX/keyryx/internal/statement"
)

const (
	// ChallengeTTL is how long a challenge can be answered.
	ChallengeTTL = time.Minute
	// MaxLive bounds the keys of one name that are published at once: the
	// current key, its renewal, and room for a restart or two.
	MaxLive = 4
	// MinLifetime is the shortest life a statement is issued for.
	MinLifetime = policy.MinLifetime
	// maxChallenges bounds the challenges one consumer has outstanding; the
	// oldest is dropped for a new one.
	maxChallenges = 16
)

var (
	ErrNotDelegated = errors.New("certify: no delegated key with that name is declared")
	ErrNoChallenge  = errors.New("certify: no such challenge for this consumer and name, or it expired")
	ErrBadKey       = errors.New("certify: the key offered is not one custody certifies")
	ErrBadProof     = errors.New("certify: the proof does not verify under the key offered")
	ErrKidKnown     = errors.New("certify: that key is already certified")
	ErrKidRevoked   = errors.New("certify: that key was revoked and is never certified again")
	ErrLifetime     = errors.New("certify: the life asked is out of range")
	ErrTooManyLive  = errors.New("certify: the name holds as many live keys as it may")
	ErrUnknownKid   = errors.New("certify: no statement has that key id")
)

// Request is a delegate request.
type Request struct {
	JWK       []byte
	Challenge string
	Proof     []byte
	Lifetime  time.Duration
}

// Entry is one statement in the inventory.
type Entry struct {
	Statement statement.Statement
	Revoked   int64
}

type entry struct {
	st      statement.Statement
	raw     []byte
	revoked int64
}

type challenge struct {
	consumer, name string
	expires        time.Time
}

// Registry holds the issued statements. Safe for concurrent use.
type Registry struct {
	mu         sync.Mutex
	dir        string
	store      *keystore.Store
	pol        *policy.Policy
	ahead      time.Duration
	now        func() time.Time
	byKid      map[string]*entry
	byName     map[string][]*entry
	challenges map[string]challenge
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type fileRec struct {
	Revoked   int64           `json:"revoked"`
	Statement json.RawMessage `json:"statement"`
	V         int             `json:"v"`
}

// Open reads every issued statement under dir/statements and verifies each
// whole under the store's root. Anything it cannot vouch for refuses the open.
func Open(dir string, store *keystore.Store, p *policy.Policy, ahead time.Duration, now func() time.Time) (*Registry, error) {
	r := &Registry{dir: dir, store: store, pol: p, ahead: ahead, now: now,
		byKid: map[string]*entry{}, byName: map[string][]*entry{}, challenges: map[string]challenge{}}
	base := filepath.Join(dir, "statements")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", base, err)
	}
	names, err := os.ReadDir(base)
	if err != nil {
		return nil, err
	}
	roots := statement.StoreRoots(store)
	for _, n := range names {
		if !n.IsDir() || !nameRe.MatchString(n.Name()) {
			return nil, fmt.Errorf("%s holds %q, which is not a statement directory this service writes", base, n.Name())
		}
		files, err := os.ReadDir(filepath.Join(base, n.Name()))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if strings.HasPrefix(f.Name(), ".tmp-") {
				continue // a write that died before its rename
			}
			e, err := load(filepath.Join(base, n.Name(), f.Name()), n.Name(), f.Name(), roots)
			if err != nil {
				return nil, err
			}
			if r.byKid[e.st.Kid] != nil {
				return nil, fmt.Errorf("two statements certify %s; this service certifies a key once", e.st.Kid)
			}
			r.byKid[e.st.Kid] = e
			r.byName[e.st.Name] = append(r.byName[e.st.Name], e)
		}
	}
	return r, nil
}

func load(path, dirName, file string, roots statement.RootKey) (*entry, error) {
	refuse := func(why string) (*entry, error) {
		return nil, fmt.Errorf("the statement %s %s; this service never writes one", path, why)
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- a file in this service's own data directory
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var rec fileRec
	if err := dec.Decode(&rec); err != nil {
		return refuse("is not a record: " + err.Error())
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return refuse("carries data after its record")
	}
	if rec.V != 1 || rec.Revoked < 0 || rec.Statement == nil {
		return refuse("is not a version 1 record")
	}
	st, err := statement.Verify(rec.Statement, roots)
	if err != nil {
		return refuse("does not verify under this store's root: " + err.Error())
	}
	if st.Name != dirName || st.Kid+".json" != file {
		return refuse("is filed under another name or key id than it certifies")
	}
	return &entry{st: st, raw: []byte(rec.Statement), revoked: rec.Revoked}, nil
}

func (r *Registry) delegated(name string) (policy.Key, bool) {
	k, ok := r.pol.Key(name)
	return k, ok && k.Mode == policy.Delegated
}

func (r *Registry) overlap(name string) time.Duration {
	if k, ok := r.delegated(name); ok {
		return k.Overlap
	}
	return policy.DefaultOverlap
}

// rootsPublished reports which root kids are still published, so a
// statement whose root was revoked is not.
func (r *Registry) rootsPublished() map[string]bool {
	out := map[string]bool{}
	for _, name := range []string{statement.RootES384, statement.RootMLDSA} {
		recs, _ := r.store.Published(name)
		for _, rec := range recs {
			out[rec.Kid] = true
		}
	}
	return out
}

// live reports whether e is in its name's key set at now.
func (r *Registry) live(e *entry, roots map[string]bool, now time.Time) bool {
	if e.revoked != 0 || !roots[e.st.Roots.ES384] || !roots[e.st.Roots.MLDSA65] {
		return false
	}
	return now.Before(time.Unix(e.st.NotAfter, 0).Add(r.overlap(e.st.Name)))
}

func random(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Challenge issues a challenge to consumer for name, answerable once, within
// ChallengeTTL.
func (r *Registry) Challenge(consumer, name string) (string, int64, error) {
	if _, ok := r.delegated(name); !ok {
		return "", 0, ErrNotDelegated
	}
	c, err := random(32)
	if err != nil {
		return "", 0, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	oldest, mine := "", 0
	for k, ch := range r.challenges {
		if !now.Before(ch.expires) {
			delete(r.challenges, k)
			continue
		}
		if ch.consumer == consumer {
			mine++
			if oldest == "" || ch.expires.Before(r.challenges[oldest].expires) {
				oldest = k
			}
		}
	}
	if mine >= maxChallenges {
		delete(r.challenges, oldest)
	}
	exp := now.Add(ChallengeTTL)
	r.challenges[c] = challenge{consumer: consumer, name: name, expires: exp}
	return c, exp.Unix(), nil
}

// Delegate certifies the key in req for consumer under name. The challenge is
// used up by any attempt. record is called with the statement before it is
// kept or published: when it fails, nothing is (no key certified with no
// record of it, CLAUDE.md invariant 18).
func (r *Registry) Delegate(consumer, name string, req Request, record func(statement.Statement, []byte) error) (statement.Statement, []byte, error) {
	key, ok := r.delegated(name)
	if !ok {
		return statement.Statement{}, nil, ErrNotDelegated
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	ch, found := r.challenges[req.Challenge]
	delete(r.challenges, req.Challenge)
	if !found || ch.consumer != consumer || ch.name != name || !now.Before(ch.expires) {
		return statement.Statement{}, nil, ErrNoChallenge
	}
	if req.Lifetime < MinLifetime || req.Lifetime > key.MaxLifetime {
		return statement.Statement{}, nil, fmt.Errorf("%w: %s, and %s allows %s to %s", ErrLifetime, req.Lifetime, name, MinLifetime, key.MaxLifetime)
	}
	jwk, pub, err := statement.ParseJWK(req.JWK, key.Alg)
	if err != nil {
		return statement.Statement{}, nil, fmt.Errorf("%w: %v", ErrBadKey, err)
	}
	if err := keystore.Verify(key.Alg, pub, statement.ProofInput(name, consumer, jwk.Kid, req.Challenge), req.Proof); err != nil {
		return statement.Statement{}, nil, ErrBadProof
	}
	if e := r.byKid[jwk.Kid]; e != nil {
		if e.revoked != 0 {
			return statement.Statement{}, nil, ErrKidRevoked
		}
		return statement.Statement{}, nil, ErrKidKnown
	}
	roots := r.rootsPublished()
	liveNow, validAhead := 0, false
	for _, e := range r.byName[name] {
		if !r.live(e, roots, now) {
			continue
		}
		liveNow++
		if e.st.ValidAt(now.Add(r.ahead)) {
			validAhead = true
		}
	}
	if liveNow >= MaxLive {
		return statement.Statement{}, nil, ErrTooManyLive
	}
	notBefore := now
	if validAhead {
		notBefore = now.Add(r.ahead)
	}
	jti, err := random(16)
	if err != nil {
		return statement.Statement{}, nil, err
	}
	raw, err := statement.Sign(statement.Statement{V: 1, Iss: statement.Issuer, Name: name, Owner: consumer, Kid: jwk.Kid, JWK: jwk,
		NotBefore: notBefore.Unix(), NotAfter: notBefore.Add(req.Lifetime).Unix(), IssuedAt: now.Unix(), JTI: jti}, r.store)
	if err != nil {
		return statement.Statement{}, nil, err
	}
	// Read back what was signed: the statement answered is the one that
	// verifies, roots included.
	st, err := statement.Verify(raw, statement.StoreRoots(r.store))
	if err != nil {
		return statement.Statement{}, nil, fmt.Errorf("certify: the statement just signed does not verify: %w", err)
	}
	if err := record(st, raw); err != nil {
		return statement.Statement{}, nil, err
	}
	e := &entry{st: st, raw: raw}
	if err := r.persist(e); err != nil {
		return statement.Statement{}, nil, err
	}
	r.byKid[st.Kid] = e
	r.byName[name] = append(r.byName[name], e)
	return st, raw, nil
}

// persist writes a statement record atomically.
func (r *Registry) persist(e *entry) error {
	b, err := json.Marshal(fileRec{Revoked: e.revoked, Statement: e.raw, V: 1})
	if err != nil {
		return err
	}
	dir := filepath.Join(r.dir, "statements", e.st.Name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, e.st.Kid+".json")); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- this service's own statement directory
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Published lists the key set of a delegated name: every key certified for
// it, not revoked, under a root still published, up to its not_after plus
// the overlap. False when the name is neither declared delegated nor has a
// statement on file.
func (r *Registry) Published(name string) ([]map[string]any, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, declared := r.delegated(name)
	entries := r.byName[name]
	if !declared && len(entries) == 0 {
		return nil, false
	}
	roots, now := r.rootsPublished(), r.now()
	var live []*entry
	for _, e := range entries {
		if r.live(e, roots, now) {
			live = append(live, e)
		}
	}
	sort.SliceStable(live, func(i, j int) bool { return live[i].st.NotBefore < live[j].st.NotBefore })
	out := []map[string]any{}
	for _, e := range live {
		j := e.st.JWK
		out = append(out, map[string]any{"kty": j.Kty, "crv": j.Crv, "x": j.X, "y": j.Y, "kid": j.Kid, "alg": j.Alg, "use": j.Use})
	}
	return out, true
}

// Statement returns the statement that certified kid, and when it was
// revoked (0 when it was not).
func (r *Registry) Statement(kid string) ([]byte, int64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.byKid[kid]
	if e == nil {
		return nil, 0, false
	}
	return append([]byte(nil), e.raw...), e.revoked, true
}

// Revoke takes a delegated key out of its key set for good.
func (r *Registry) Revoke(kid string) (statement.Statement, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.byKid[kid]
	if e == nil {
		return statement.Statement{}, ErrUnknownKid
	}
	if e.revoked != 0 {
		return e.st, nil
	}
	e.revoked = r.now().Unix()
	if err := r.persist(e); err != nil {
		e.revoked = 0
		return statement.Statement{}, err
	}
	return e.st, nil
}

// Alarms lists the statement states custody could not vouch for. Scaffold.
func (r *Registry) Alarms() []keystore.Alarm { return nil }

// Inventory lists every statement, revoked ones included, by name then age.
func (r *Registry) Inventory() []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Entry
	for _, e := range r.byKid {
		out = append(out, Entry{Statement: e.st, Revoked: e.revoked})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Statement, out[j].Statement
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.IssuedAt != b.IssuedAt {
			return a.IssuedAt < b.IssuedAt
		}
		return a.Kid < b.Kid
	})
	return out
}
