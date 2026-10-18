package witness

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/statement"
)

// The witness takes a checkpoint key on custody's word, so that word must be
// a statement both halves of the delegation root signed, for that kid, valid
// then, and not revoked before the witness saw the record; and the root must
// be the one the witness pinned, not whatever custody, or something on the
// path to it, serves today.

// fakeCustody serves one key's statement and a delegation root's key set,
// both from a root store that a test can swap.
type fakeCustody struct {
	mu      sync.Mutex
	t       *testing.T
	roots   []*keystore.Store // the key sets served, together
	signer  *keystore.Store   // the root that signs the statement
	jwk     statement.JWK
	name    string
	revoked int64
	down    bool
	// stmtsDown is the statements route alone failing; garbled serves a
	// root key set that does not read.
	stmtsDown, garbled bool
	srv                *httptest.Server
}

func rootStore(t *testing.T, b byte) *keystore.Store {
	t.Helper()
	d := filepath.Join(t.TempDir(), "custody")
	_ = os.Mkdir(d, 0o700)
	s, err := keystore.Open(d, [32]byte{7, b}, statement.RootKeys, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newFakeCustody(t *testing.T, pub *ecdsa.PublicKey, name string) *fakeCustody {
	t.Helper()
	b, _ := json.Marshal(delegation.FromPublic(pub, ""))
	jwk, _, err := statement.ParseJWK(b, "ES256")
	if err != nil {
		t.Fatal(err)
	}
	a := rootStore(t, 1)
	f := &fakeCustody{t: t, roots: []*keystore.Store{a}, signer: a, jwk: jwk, name: name}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCustody) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down || (f.stmtsDown && strings.HasPrefix(r.URL.Path, "/v1/statements/")) {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	switch r.URL.Path {
	case "/v1/jwks/" + statement.RootName:
		if f.garbled {
			_, _ = w.Write([]byte(`{"keys": [{"kty": "oct"}]}`))
			return
		}
		var keys []map[string]any
		for _, s := range f.roots {
			for _, n := range []string{statement.RootES384, statement.RootMLDSA} {
				recs, _ := s.Published(n)
				for _, rec := range recs {
					keys = append(keys, keystore.JWK(rec))
				}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	case "/v1/statements/" + f.jwk.Kid:
		raw, err := statement.Sign(statement.Statement{V: 1, Iss: statement.Issuer, Name: f.name, Owner: "wardryx", Kid: f.jwk.Kid, JWK: f.jwk,
			NotBefore: t0.Unix(), NotAfter: t0.Add(24 * time.Hour).Unix(), IssuedAt: t0.Unix(), JTI: "jti-custody-0123456789"}, f.signer)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"statement": json.RawMessage(raw), "revoked_at": f.revoked})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// kidsOf is a root store's published kids, sorted, as RootKids answers them.
func kidsOf(stores ...*keystore.Store) []string {
	var out []string
	for _, s := range stores {
		for _, n := range []string{statement.RootES384, statement.RootMLDSA} {
			recs, _ := s.Published(n)
			for _, r := range recs {
				out = append(out, r.Kid)
			}
		}
	}
	sort.Strings(out)
	return out
}

func TestTheCustodyClientTakesAKeyOnlyOnAStatementThatHolds(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := newFakeCustody(t, &k.PublicKey, "wardryx-stream")
	pub, _ := k.PublicKey.Bytes()
	c := &CustodyKeys{Base: f.srv.URL, HTTP: f.srv.Client(), TTL: time.Nanosecond}
	kids, err := c.RootKids(t0)
	if err != nil {
		t.Fatal(err)
	}
	c.Pin(kids)
	got, err := c.Key(f.jwk.Kid, t0.Add(time.Minute), t0.Add(2*time.Minute))
	if err != nil || string(got.Public) != string(pub) || got.Name != "wardryx-stream" || got.Owner != "wardryx" {
		t.Fatalf("an honest statement: %+v %v", got, err)
	}
	for what, call := range map[string]func() error{
		"a kid no statement certifies": func() error { _, err := c.Key(strings.Repeat("B", 43), t0, t0); return err },
		"a record before not_before":   func() error { _, err := c.Key(f.jwk.Kid, t0.Add(-time.Second), t0); return err },
		"a record after not_after":     func() error { _, err := c.Key(f.jwk.Kid, t0.Add(25*time.Hour), t0.Add(25*time.Hour)); return err },
		"a key revoked before the witness saw the record": func() error {
			f.revoked = t0.Add(30 * time.Minute).Unix()
			_, err := c.Key(f.jwk.Kid, t0.Add(time.Minute), t0.Add(40*time.Minute))
			return err
		},
	} {
		f.revoked = 0
		if call() == nil {
			t.Errorf("%s: a key was taken", what)
		}
	}
	f.revoked = t0.Add(30 * time.Minute).Unix()
	if _, err := c.Key(f.jwk.Kid, t0.Add(time.Minute), t0.Add(10*time.Minute)); err != nil {
		t.Fatalf("a record seen before its key was revoked: %v", err)
	}
	f.revoked = 0
	if _, err := (&CustodyKeys{Base: f.srv.URL, HTTP: f.srv.Client()}).Key(f.jwk.Kid, t0, t0); err == nil {
		t.Fatal("a client that pinned no root took a key")
	}
}

func TestTheCustodyClientUsesOnlyThePinnedRoot(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := newFakeCustody(t, &k.PublicKey, "wardryx-stream")
	a := f.signer
	c := &CustodyKeys{Base: f.srv.URL, HTTP: f.srv.Client(), TTL: time.Nanosecond}
	c.Pin(kidsOf(a))
	if _, err := c.Key(f.jwk.Kid, t0.Add(time.Minute), t0.Add(time.Minute)); err != nil {
		t.Fatalf("control: under the pinned root: %v", err)
	}
	// Custody, or something on the path to it, serves another root and a
	// statement that root signed.
	b := rootStore(t, 2)
	f.mu.Lock()
	f.roots, f.signer = []*keystore.Store{b}, b
	f.mu.Unlock()
	served, err := c.RootKids(t0.Add(2 * time.Minute))
	if err != nil || fmt.Sprint(served) != fmt.Sprint(kidsOf(b)) {
		t.Fatalf("RootKids does not say what is served: %v %v", served, err)
	}
	if _, err := c.Key(f.jwk.Kid, t0.Add(time.Minute), t0.Add(3*time.Minute)); err == nil {
		t.Fatal("a statement under a root the witness never pinned was taken")
	}
	// The pinned root served beside the other one: only the pinned keys count.
	f.mu.Lock()
	f.roots = []*keystore.Store{a, b}
	f.mu.Unlock()
	if _, err := c.Key(f.jwk.Kid, t0.Add(time.Minute), t0.Add(4*time.Minute)); err == nil {
		t.Fatal("a statement signed by an unpinned root served beside the pinned one was taken")
	}
	c.Pin(kidsOf(b))
	if _, err := c.Key(f.jwk.Kid, t0.Add(time.Minute), t0.Add(5*time.Minute)); err != nil {
		t.Fatalf("after the operator re-pins: %v", err)
	}
	f.mu.Lock()
	f.down = true
	f.mu.Unlock()
	if _, err := c.Key(f.jwk.Kid, t0.Add(time.Minute), t0.Add(6*time.Minute)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("custody down: %v, want ErrUnavailable", err)
	}
	if _, err := c.RootKids(t0.Add(7 * time.Minute)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("custody down, the root set: %v, want ErrUnavailable", err)
	}
}

// The witness pins the delegation root it first accepts in its own signed
// log. A different set served later is a high finding, and is never used.
func TestAChangedDelegationRootIsAHighFindingAndIsNotUsed(t *testing.T) {
	s := newStand(t, nil)
	f := newFakeCustody(t, &s.key.PublicKey, "wardryx-stream")
	s.custody = &CustodyKeys{Base: f.srv.URL, HTTP: f.srv.Client(), TTL: time.Nanosecond}
	s.restart()
	s.emit("wardryx.ndjson", 2)
	s.checkpoint("wardryx.ndjson", "checkpoint", true, nil)
	if got := s.tick(); len(got) != 0 {
		t.Fatalf("control: %+v", got)
	}
	pinned := false
	for _, e := range s.log.Entries() {
		if e.Kind == "delegation_root" && fmt.Sprint(e.Kids) == fmt.Sprint(kidsOf(f.signer)) {
			pinned = true
		}
	}
	if !pinned {
		t.Fatal("the root the witness first accepted is not pinned in its log")
	}
	b := rootStore(t, 3)
	f.mu.Lock()
	f.roots, f.signer = []*keystore.Store{b}, b
	f.mu.Unlock()
	s.emit("wardryx.ndjson", 1)
	s.checkpoint("wardryx.ndjson", "checkpoint", true, nil)
	findings := s.tick()
	rootFinding, recordRefused := false, false
	for _, fd := range findings {
		if fd.Type == "witness_checkpoint_invalid" && fd.Severity == "high" && fd.Data["subject"] == "delegation-root" {
			rootFinding = true
		}
		if fd.Type == "witness_checkpoint_invalid" && fd.Data["count"] == int64(3) {
			recordRefused = true
		}
	}
	if !rootFinding || !recordRefused {
		t.Fatalf("a swapped delegation root: %+v", findings)
	}
	// Once per set: the next interval says nothing new about the root.
	for _, fd := range s.tick() {
		if fd.Data["subject"] == RootSubject {
			t.Fatalf("the same changed root was reported twice: %+v", fd)
		}
	}
	// After a restart the pin is still the one in the log.
	s.restart()
	s.emit("wardryx.ndjson", 1)
	s.checkpoint("wardryx.ndjson", "checkpoint", true, nil)
	again := false
	for _, fd := range s.tick() {
		if fd.Type == "witness_checkpoint_invalid" && fd.Data["count"] == int64(4) {
			again = true
		}
	}
	if !again {
		t.Fatal("after a restart a statement under the swapped root was taken")
	}
	// The operator re-pins: the new root is used, and the re-pin is logged.
	s.cfg.RootPin = kidsOf(b)
	s.restart()
	s.emit("wardryx.ndjson", 1)
	s.checkpoint("wardryx.ndjson", "checkpoint", true, nil)
	if got := s.tick(); len(got) != 0 {
		t.Fatalf("after a re-pin: %+v", got)
	}
	// A key set that does not read is a finding about the root too.
	f.mu.Lock()
	f.garbled = true
	f.mu.Unlock()
	got := s.tick()
	if len(got) != 1 || got[0].Severity != "high" || got[0].Data["subject"] != RootSubject || !strings.Contains(fmt.Sprint(got[0].Data["reason"]), "does not read") {
		t.Fatalf("a root key set that does not read: %+v", got)
	}
}

// Custody unreachable is not a record that does not hold: the checkpoint
// waits, as one ahead of the stream does, and nothing is raised. That holds
// before any root is pinned, with only the statements failing, and with
// custody down after the pin.
func TestACheckpointWaitsWhileCustodyIsUnreachable(t *testing.T) {
	s := newStand(t, nil)
	f := newFakeCustody(t, &s.key.PublicKey, "wardryx-stream")
	s.custody = &CustodyKeys{Base: f.srv.URL, HTTP: f.srv.Client(), TTL: time.Nanosecond}
	s.restart()
	set := func(down, stmtsDown bool) {
		f.mu.Lock()
		f.down, f.stmtsDown = down, stmtsDown
		f.mu.Unlock()
	}
	accepted := func(count int64) int {
		n := 0
		for _, e := range s.log.Entries() {
			if e.Kind == "checkpoint" && e.Count == count {
				n++
			}
		}
		return n
	}
	set(true, false)
	s.emit("wardryx.ndjson", 2)
	s.checkpoint("wardryx.ndjson", "checkpoint", true, nil)
	if got := s.tick(); len(got) != 0 {
		t.Fatalf("custody down before any root was pinned raised %+v", got)
	}
	set(false, true)
	if got := s.tick(); len(got) != 0 {
		t.Fatalf("custody's statements down raised %+v", got)
	}
	set(false, false)
	if got := s.tick(); len(got) != 0 || accepted(2) != 1 {
		t.Fatalf("custody back: %+v, the record that waited accepted %d times", got, accepted(2))
	}
	s.emit("wardryx.ndjson", 1)
	set(true, false)
	s.checkpoint("wardryx.ndjson", "checkpoint", true, nil)
	if got := s.tick(); len(got) != 0 {
		t.Fatalf("custody down after the pin raised %+v", got)
	}
	set(false, false)
	if got := s.tick(); len(got) != 0 || accepted(3) != 1 {
		t.Fatalf("custody back after the pin: %+v, accepted %d times", got, accepted(3))
	}
}
