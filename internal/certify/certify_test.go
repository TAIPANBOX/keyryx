package certify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/policy"
	"github.com/TAIPANBOX/keyryx/internal/statement"
)

// Certifying a key is saying "this key is that consumer's, until then". A
// statement issued for a key the consumer does not hold, or one that outlives
// its not_after, is a key nobody vouched for that every verifier accepts.

var t0 = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

const ahead = 15 * time.Minute

type stand struct {
	t     *testing.T
	dir   string
	root  [32]byte
	now   time.Time
	pol   *policy.Policy
	store *keystore.Store
	reg   *Registry
}

func testPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(`{"version":1,
 "keys":[{"name":"wardryx-approval","alg":"ES256"},
  {"name":"vouchryx-token","alg":"ES256","mode":"delegated","max_lifetime":"72h","overlap":"10m"},
  {"name":"wardryx-stream","alg":"ES256","mode":"delegated","max_lifetime":"24h"}],
 "consumers":[
  {"name":"vouchryx","auth":{"socket":"vouchryx"},"grants":{"vouchryx-token":["delegate"]}},
  {"name":"wardryx","auth":{"socket":"wardryx"},"grants":{"wardryx-approval":["sign"],"wardryx-stream":["delegate"]}}]}`))
	if err != nil {
		t.Fatalf("the test policy did not parse: %v", err)
	}
	return p
}

func newStand(t *testing.T) *stand {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s := &stand{t: t, dir: dir, root: [32]byte{5, 4, 3, 2, 1}, now: t0, pol: testPolicy(t)}
	s.reopen()
	return s
}

func (s *stand) clock() time.Time { return s.now }

func (s *stand) reopen() {
	s.t.Helper()
	keys := append(s.pol.HeldKeys(), statement.RootKeys...)
	store, err := keystore.Open(s.dir, s.root, keys, s.clock)
	if err != nil {
		s.t.Fatalf("keystore.Open: %v", err)
	}
	reg, err := Open(s.dir, store, s.pol, ahead, s.clock)
	if err != nil {
		s.t.Fatalf("certify.Open: %v", err)
	}
	s.store, s.reg = store, reg
}

type holder struct {
	key *ecdsa.PrivateKey
	jwk []byte
	kid string
}

func newHolder(t *testing.T) holder {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j := delegation.FromPublic(&k.PublicKey, "")
	kid, _ := delegation.Thumbprint(j)
	b, _ := json.Marshal(j)
	return holder{key: k, jwk: b, kid: kid}
}

func (h holder) prove(t *testing.T, name, consumer, challenge string) []byte {
	t.Helper()
	d := sha256.Sum256(statement.ProofInput(name, consumer, h.kid, challenge))
	r, sig, err := ecdsa.Sign(rand.Reader, h.key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return append(r.FillBytes(make([]byte, 32)), sig.FillBytes(make([]byte, 32))...)
}

var logged []string

func record(st statement.Statement, raw []byte) error {
	logged = append(logged, st.Kid)
	return nil
}

// certify runs the honest flow: a challenge, a proof over it, a statement.
func (s *stand) certify(h holder, consumer, name string, life time.Duration) (statement.Statement, []byte, error) {
	s.t.Helper()
	c, _, err := s.reg.Challenge(consumer, name)
	if err != nil {
		return statement.Statement{}, nil, err
	}
	return s.reg.Delegate(consumer, name, Request{JWK: h.jwk, Challenge: c, Proof: h.prove(s.t, name, consumer, c), Lifetime: life}, record)
}

func (s *stand) published(name string) map[string]bool {
	s.t.Helper()
	keys, _ := s.reg.Published(name)
	out := map[string]bool{}
	for _, k := range keys {
		kid, _ := k["kid"].(string)
		out[kid] = true
	}
	return out
}

func TestAKeyIsCertifiedOnlyWithAProofOfPossession(t *testing.T) {
	s := newStand(t)
	h, other := newHolder(t), newHolder(t)
	const name, who = "vouchryx-token", "vouchryx"
	logged = nil
	try := func(what string, consumer, asName string, req Request) {
		t.Helper()
		if _, _, err := s.reg.Delegate(consumer, asName, req, record); err == nil {
			t.Errorf("%s: a statement was issued", what)
		}
	}
	c1, _, _ := s.reg.Challenge(who, name)
	c2, _, _ := s.reg.Challenge(who, name)
	try("a proof by another key", who, name, Request{JWK: h.jwk, Challenge: c1, Proof: other.prove(t, name, who, c1), Lifetime: time.Hour})
	try("the challenge used a second time, honestly now", who, name, Request{JWK: h.jwk, Challenge: c1, Proof: h.prove(t, name, who, c1), Lifetime: time.Hour})
	try("a proof over another challenge", who, name, Request{JWK: h.jwk, Challenge: c2, Proof: h.prove(t, name, who, "not-"+c2), Lifetime: time.Hour})
	c3, _, _ := s.reg.Challenge(who, name)
	try("a challenge presented by another consumer", "wardryx", name, Request{JWK: h.jwk, Challenge: c3, Proof: h.prove(t, name, "wardryx", c3), Lifetime: time.Hour})
	c4, _, _ := s.reg.Challenge(who, name)
	try("a challenge presented for another name", who, "wardryx-stream", Request{JWK: h.jwk, Challenge: c4, Proof: h.prove(t, "wardryx-stream", who, c4), Lifetime: time.Hour})
	c5, exp, _ := s.reg.Challenge(who, name)
	if exp != t0.Add(ChallengeTTL).Unix() {
		t.Errorf("the challenge expires at %d, want %d", exp, t0.Add(ChallengeTTL).Unix())
	}
	s.now = t0.Add(ChallengeTTL + time.Second)
	try("an expired challenge", who, name, Request{JWK: h.jwk, Challenge: c5, Proof: h.prove(t, name, who, c5), Lifetime: time.Hour})
	try("a challenge never issued", who, name, Request{JWK: h.jwk, Challenge: "made-up", Proof: h.prove(t, name, who, "made-up"), Lifetime: time.Hour})
	if _, _, err := s.reg.Challenge("vouchryx", "wardryx-approval"); err == nil {
		t.Error("a challenge was issued for a held key")
	}
	if len(logged) != 0 || len(s.published(name)) != 0 {
		t.Fatalf("a refusal reached the record (%v) or the key set (%v)", logged, s.published(name))
	}
	st, raw, err := s.certify(h, who, name, time.Hour)
	if err != nil {
		t.Fatalf("the honest proof was refused: %v", err)
	}
	if st.Kid != h.kid || st.Owner != who || st.Name != name || len(logged) != 1 || !s.published(name)[h.kid] {
		t.Fatalf("statement %+v, logged %v, published %v", st, logged, s.published(name))
	}
	if _, err := statement.Verify(raw, statement.StoreRoots(s.store)); err != nil {
		t.Fatalf("the issued statement does not verify: %v", err)
	}
}

func TestNotAfterIsHonoured(t *testing.T) {
	s := newStand(t)
	for _, life := range []time.Duration{73 * time.Hour, MinLifetime - time.Second, 0, -time.Hour} {
		if _, _, err := s.certify(newHolder(t), "vouchryx", "vouchryx-token", life); !errors.Is(err, ErrLifetime) {
			t.Errorf("a life of %s: %v, want ErrLifetime", life, err)
		}
	}
	st, _, err := s.certify(newHolder(t), "vouchryx", "vouchryx-token", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if st.NotBefore != t0.Unix() || st.NotAfter != t0.Add(24*time.Hour).Unix() || st.IssuedAt != t0.Unix() {
		t.Fatalf("not_before %d, not_after %d, issued_at %d", st.NotBefore, st.NotAfter, st.IssuedAt)
	}
	nb, na := time.Unix(st.NotBefore, 0), time.Unix(st.NotAfter, 0)
	for at, want := range map[time.Time]bool{nb.Add(-time.Second): false, nb: true, na.Add(-time.Second): true, na: false, na.Add(time.Hour): false} {
		if st.ValidAt(at) != want {
			t.Errorf("valid at %s: %v, want %v", at, !want, want)
		}
	}
}

func TestTheOverlapKeepsAnExpiredKeyPublishedForItsWindow(t *testing.T) {
	s := newStand(t)
	h := newHolder(t)
	st, _, err := s.certify(h, "vouchryx", "vouchryx-token", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	na := time.Unix(st.NotAfter, 0)
	s.now = na.Add(time.Second)
	if !s.published("vouchryx-token")[h.kid] {
		t.Fatal("a key a second past not_after left the key set; a token it signed a minute ago is still live")
	}
	k, _ := s.pol.Key("vouchryx-token")
	s.now = na.Add(k.Overlap + time.Second)
	if s.published("vouchryx-token")[h.kid] {
		t.Fatalf("a key %s past not_after is still published, over its %s overlap", k.Overlap+time.Second, k.Overlap)
	}
	// The default overlap, for a name that states none.
	h2 := newHolder(t)
	st2, _, err := s.certify(h2, "wardryx", "wardryx-stream", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s.now = time.Unix(st2.NotAfter, 0).Add(policy.DefaultOverlap - time.Second)
	if !s.published("wardryx-stream")[h2.kid] {
		t.Fatal("the default overlap was not kept")
	}
	s.now = time.Unix(st2.NotAfter, 0).Add(policy.DefaultOverlap + time.Second)
	if s.published("wardryx-stream")[h2.kid] {
		t.Fatal("the default overlap was exceeded")
	}
}

func TestARenewalIsPublishedBeforeItSigns(t *testing.T) {
	s := newStand(t)
	first, second := newHolder(t), newHolder(t)
	a, _, err := s.certify(first, "vouchryx", "vouchryx-token", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if a.NotBefore != s.now.Unix() {
		t.Fatalf("with no valid key the first may sign at once; not_before is %s after now", time.Duration(a.NotBefore-s.now.Unix())*time.Second)
	}
	s.now = t0.Add(12 * time.Hour)
	b, _, err := s.certify(second, "vouchryx", "vouchryx-token", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if b.NotBefore != s.now.Add(ahead).Unix() || b.NotAfter != s.now.Add(ahead+24*time.Hour).Unix() {
		t.Fatalf("a renewal must wait the publish-ahead time: not_before %d, want %d; not_after %d", b.NotBefore, s.now.Add(ahead).Unix(), b.NotAfter)
	}
	if b.ValidAt(s.now) || !b.ValidAt(s.now.Add(ahead)) {
		t.Fatal("the renewal's validity does not start at its not_before")
	}
	p := s.published("vouchryx-token")
	if !p[first.kid] || !p[second.kid] || len(p) != 2 {
		t.Fatalf("both keys must be published from the moment they are certified: %v", p)
	}
	// A late renewal, when the current key ends inside the publish-ahead
	// time, may sign at once: waiting would leave no valid key at all.
	s.now = time.Unix(b.NotAfter, 0).Add(-5 * time.Minute)
	c, _, err := s.certify(newHolder(t), "vouchryx", "vouchryx-token", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if c.NotBefore != s.now.Unix() {
		t.Fatalf("a late renewal waits %ds and leaves a gap", c.NotBefore-s.now.Unix())
	}
}

func TestAKidIsCertifiedOnceAndARevokedKidNever(t *testing.T) {
	s := newStand(t)
	h := newHolder(t)
	if _, _, err := s.certify(h, "vouchryx", "vouchryx-token", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.certify(h, "vouchryx", "vouchryx-token", time.Hour); !errors.Is(err, ErrKidKnown) {
		t.Fatalf("the same key certified twice: %v", err)
	}
	if _, _, err := s.certify(h, "wardryx", "wardryx-stream", time.Hour); err == nil {
		t.Fatal("a key certified for one name was certified again for another")
	}
	st, err := s.reg.Revoke(h.kid)
	if err != nil || st.Kid != h.kid {
		t.Fatalf("Revoke: %+v %v", st, err)
	}
	if s.published("vouchryx-token")[h.kid] {
		t.Fatal("a revoked key is still published")
	}
	if _, rev, ok := s.reg.Statement(h.kid); !ok || rev != t0.Unix() {
		t.Fatalf("the revoked statement: ok %v revoked %d", ok, rev)
	}
	if _, _, err := s.certify(h, "vouchryx", "vouchryx-token", time.Hour); err == nil {
		t.Fatal("a revoked key was certified again")
	}
	if s.published("vouchryx-token")[h.kid] {
		t.Fatal("a revoked key came back")
	}
	if _, err := s.reg.Revoke("no-such-kid"); !errors.Is(err, ErrUnknownKid) {
		t.Fatalf("revoking an unknown kid: %v", err)
	}
}

func TestTheLiveKeysOfANameAreCapped(t *testing.T) {
	s := newStand(t)
	var last statement.Statement
	for i := 0; i < MaxLive; i++ {
		st, _, err := s.certify(newHolder(t), "vouchryx", "vouchryx-token", time.Hour)
		if err != nil {
			t.Fatalf("key %d of %d: %v", i+1, MaxLive, err)
		}
		last = st
	}
	if _, _, err := s.certify(newHolder(t), "vouchryx", "vouchryx-token", time.Hour); !errors.Is(err, ErrTooManyLive) {
		t.Fatalf("key %d: %v, want ErrTooManyLive", MaxLive+1, err)
	}
	if n := len(s.published("vouchryx-token")); n != MaxLive {
		t.Fatalf("%d published, want %d", n, MaxLive)
	}
	k, _ := s.pol.Key("vouchryx-token")
	s.now = time.Unix(last.NotAfter, 0).Add(k.Overlap + time.Second)
	if _, _, err := s.certify(newHolder(t), "vouchryx", "vouchryx-token", time.Hour); err != nil {
		t.Fatalf("once the others expired out of their overlap: %v", err)
	}
}

func statementFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.Walk(filepath.Join(dir, "statements"), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	return out
}

func TestStatementsSurviveARestartAndAnEditedOneRefusesTheStart(t *testing.T) {
	s := newStand(t)
	a, b, c := newHolder(t), newHolder(t), newHolder(t)
	for _, h := range []holder{a, b} {
		if _, _, err := s.certify(h, "vouchryx", "vouchryx-token", time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.certify(c, "wardryx", "wardryx-stream", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.reg.Revoke(b.kid); err != nil {
		t.Fatal(err)
	}
	s.reopen()
	if p := s.published("vouchryx-token"); !p[a.kid] || p[b.kid] || len(p) != 1 {
		t.Fatalf("after a restart: %v (a revoked key must stay revoked)", p)
	}
	if !s.published("wardryx-stream")[c.kid] {
		t.Fatal("the other name's key was lost in the restart")
	}
	files := statementFiles(t, s.dir)
	if len(files) != 3 {
		t.Fatalf("%d statement files, want 3", len(files))
	}
	var aFile, cFile string
	for _, f := range files {
		if filepath.Base(f) == a.kid+".json" && strings.Contains(f, "vouchryx-token") {
			aFile = f
		}
		if strings.Contains(f, "wardryx-stream") {
			cFile = f
		}
	}
	if aFile == "" || cFile == "" {
		t.Fatalf("statement files %v", files)
	}
	orig, _ := os.ReadFile(aFile)
	edits := map[string]func(){
		"the payload edited": func() {
			var w map[string]any
			_ = json.Unmarshal(orig, &w)
			stmt := w["statement"].(map[string]any)
			p, _ := base64.RawURLEncoding.DecodeString(stmt["payload"].(string))
			stmt["payload"] = base64.RawURLEncoding.EncodeToString(bytes.Replace(p, []byte(`"owner":"vouchryx"`), []byte(`"owner":"wardryx"`), 1))
			b, _ := json.Marshal(w)
			_ = os.WriteFile(aFile, b, 0o600)
		},
		"moved under another name": func() {
			_ = os.Rename(aFile, filepath.Join(filepath.Dir(cFile), filepath.Base(aFile)))
		},
		"renamed to another kid": func() {
			_ = os.Rename(aFile, filepath.Join(filepath.Dir(aFile), "another-kid.json"))
		},
		"an unknown member": func() {
			_ = os.WriteFile(aFile, bytes.Replace(orig, []byte(`{"revoked"`), []byte(`{"trusted":true,"revoked"`), 1), 0o600)
		},
		"garbage": func() { _ = os.WriteFile(aFile, []byte("{"), 0o600) },
		"signed by another root": func() {
			other := newStand(t)
			_, raw, err := other.certify(a, "vouchryx", "vouchryx-token", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := json.Marshal(map[string]any{"revoked": 0, "statement": json.RawMessage(raw), "v": 1})
			_ = os.WriteFile(aFile, b, 0o600)
		},
	}
	for what, edit := range edits {
		edit()
		if _, err := Open(s.dir, s.store, s.pol, ahead, s.clock); err == nil {
			t.Errorf("%s: the registry opened", what)
		}
		// Undo every kind of edit.
		_ = os.Remove(filepath.Join(filepath.Dir(cFile), filepath.Base(aFile)))
		_ = os.Remove(filepath.Join(filepath.Dir(aFile), "another-kid.json"))
		if err := os.WriteFile(aFile, orig, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(s.dir, s.store, s.pol, ahead, s.clock); err != nil {
			t.Fatalf("after undoing %q the registry still refuses: %v", what, err)
		}
	}
}

func TestRevokingARootKeyUnpublishesWhatItCertified(t *testing.T) {
	s := newStand(t)
	before := newHolder(t)
	st, _, err := s.certify(before, "vouchryx", "vouchryx-token", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.Revoke(st.Roots.ES384); err != nil {
		t.Fatalf("revoking the root's classical half: %v", err)
	}
	if s.published("vouchryx-token")[before.kid] {
		t.Fatal("a key certified by a revoked root is still published")
	}
	after := newHolder(t)
	st2, raw2, err := s.certify(after, "vouchryx", "vouchryx-token", time.Hour)
	if err != nil {
		t.Fatalf("certifying under the new root: %v", err)
	}
	if st2.Roots.ES384 == st.Roots.ES384 || !s.published("vouchryx-token")[after.kid] {
		t.Fatalf("the new statement names root %s, the revoked one was %s", st2.Roots.ES384, st.Roots.ES384)
	}
	if _, err := statement.Verify(raw2, statement.StoreRoots(s.store)); err != nil {
		t.Fatalf("the new statement: %v", err)
	}
	s.reopen()
	if s.published("vouchryx-token")[before.kid] {
		t.Fatal("after a restart, a key certified by a revoked root is published again")
	}
}

func TestACertifiedKeyIsNeverHeld(t *testing.T) {
	s := newStand(t)
	held := len(s.store.Inventory())
	var keys []holder
	for _, c := range []struct{ who, name string }{{"vouchryx", "vouchryx-token"}, {"wardryx", "wardryx-stream"}} {
		h := newHolder(t)
		if _, _, err := s.certify(h, c.who, c.name, time.Hour); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, h)
	}
	// A request that carries the private key itself is refused, and the
	// private key it carried is written nowhere.
	leaky := newHolder(t)
	var j map[string]any
	_ = json.Unmarshal(leaky.jwk, &j)
	j["d"] = base64.RawURLEncoding.EncodeToString(rawPrivate(t, leaky.key))
	withD, _ := json.Marshal(j)
	c, _, _ := s.reg.Challenge("vouchryx", "vouchryx-token")
	if _, _, err := s.reg.Delegate("vouchryx", "vouchryx-token", Request{JWK: withD, Challenge: c, Proof: leaky.prove(t, "vouchryx-token", "vouchryx", c), Lifetime: time.Hour}, record); err == nil {
		t.Fatal("a key offered with its private member was certified")
	}
	keys = append(keys, leaky)
	if n := len(s.store.Inventory()); n != held {
		t.Fatalf("the store held %d keys before certifying and %d after", held, n)
	}
	var files int
	_ = filepath.Walk(s.dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		files++
		raw, _ := os.ReadFile(p)
		for _, h := range keys {
			d := rawPrivate(t, h.key)
			for _, form := range [][]byte{d, []byte(base64.RawURLEncoding.EncodeToString(d)), []byte(base64.StdEncoding.EncodeToString(d)), []byte(hex.EncodeToString(d))} {
				if bytes.Contains(raw, form) {
					t.Fatalf("%s holds a delegated key's private member", p)
				}
			}
		}
		return nil
	})
	if files < 3 {
		t.Fatalf("searched %d files, so this test measured nothing", files)
	}
}

// rawPrivate is the private scalar, fixed width, for searching files for it.
func rawPrivate(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
