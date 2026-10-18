package keystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/keyryx/internal/policy"
)

// Every test here is about a key that signs, and the answers that go wrong
// silently: a signature from the wrong key, a key published that should not
// be, a private key on disk in the clear, a wrapped key that opens under the
// wrong name.

var (
	declared = []policy.Key{
		{Name: "approval", Alg: policy.ES256},
		{Name: "root", Alg: policy.ES384},
		{Name: "witness", Alg: policy.MLDSA65},
	}
	rootA = [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	rootB = [32]byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	t0    = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
)

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func dataDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func open(t *testing.T, dir string, root [32]byte, keys []policy.Key, c *clock) *Store {
	t.Helper()
	s, err := Open(dir, root, keys, c.Now)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func activeKid(t *testing.T, s *Store, name string) string {
	t.Helper()
	recs, ok := s.Published(name)
	if !ok {
		t.Fatalf("no key named %s is published", name)
	}
	for _, r := range recs {
		if r.State == Active {
			return r.Kid
		}
	}
	t.Fatalf("%s has no active key: %+v", name, recs)
	return ""
}

func recordFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(filepath.Join(dir, "keys"), func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(p, ".json") {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func TestAStoreCreatesAnActiveKeyForEveryDeclaredKeyAndSignsWithIt(t *testing.T) {
	c := &clock{t0}
	s := open(t, dataDir(t), rootA, declared, c)
	for _, k := range declared {
		kid := activeKid(t, s, k.Name)
		sig, err := s.Sign(k.Name, []byte("statement for "+k.Name))
		if err != nil {
			t.Fatalf("%s: Sign: %v", k.Name, err)
		}
		if sig.Kid != kid || sig.Alg != k.Alg {
			t.Fatalf("%s: signed by %s/%s, the active key is %s/%s", k.Name, sig.Kid, sig.Alg, kid, k.Alg)
		}
		if err := Verify(k.Alg, sig.Public, []byte("statement for "+k.Name), sig.Sig); err != nil {
			t.Fatalf("%s: the signature does not verify with the key it came with: %v", k.Name, err)
		}
	}
	if _, err := s.Sign("no-such-key", []byte("x")); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("a key nobody declared signed, or failed the wrong way: %v", err)
	}
}

func TestEachAlgorithmSignsInItsOwnShapeAndVerifiesOnlyItsOwnStatement(t *testing.T) {
	s := open(t, dataDir(t), rootA, declared, &clock{t0})
	sizes := map[policy.Alg]int{policy.ES256: 64, policy.ES384: 96, policy.MLDSA65: 3309}
	for _, k := range declared {
		sig, err := s.Sign(k.Name, []byte("the statement"))
		if err != nil {
			t.Fatal(err)
		}
		if len(sig.Sig) != sizes[k.Alg] {
			t.Errorf("%s: a %d-byte signature, want %d (fixed-width R||S for ECDSA, FIPS 204 for ML-DSA)", k.Alg, len(sig.Sig), sizes[k.Alg])
		}
		if err := Verify(k.Alg, sig.Public, []byte("the statement"), sig.Sig); err != nil {
			t.Errorf("%s: control: %v", k.Alg, err)
		}
		if err := Verify(k.Alg, sig.Public, []byte("another statement"), sig.Sig); err == nil {
			t.Errorf("%s: a signature verified over a statement it was not made over", k.Alg)
		}
		other := policy.ES256
		if k.Alg == policy.ES256 {
			other = policy.ES384
		}
		if err := Verify(other, sig.Public, []byte("the statement"), sig.Sig); err == nil {
			t.Errorf("%s: verified under %s", k.Alg, other)
		}
		flipped := append([]byte(nil), sig.Sig...)
		flipped[len(flipped)/2] ^= 1
		if err := Verify(k.Alg, sig.Public, []byte("the statement"), flipped); err == nil {
			t.Errorf("%s: a flipped signature verified", k.Alg)
		}
	}
}

func TestTheKeyIdIsTheThumbprintOfThePublicKey(t *testing.T) {
	s := open(t, dataDir(t), rootA, declared, &clock{t0})
	for _, k := range declared {
		recs, _ := s.Published(k.Name)
		r := recs[0]
		switch k.Alg {
		case policy.MLDSA65:
			sum := sha256.Sum256(r.Public)
			if want := "mldsa65:" + base64.RawURLEncoding.EncodeToString(sum[:]); r.Kid != want {
				t.Errorf("ML-DSA kid %q, want %q", r.Kid, want)
			}
		default:
			pub, err := ecPublic(k.Alg, r.Public)
			if err != nil {
				t.Fatal(err)
			}
			want, err := delegation.Thumbprint(delegation.FromPublic(pub, ""))
			if err != nil {
				t.Fatal(err)
			}
			if r.Kid != want {
				t.Errorf("%s kid %q, want the RFC 7638 thumbprint %q", k.Alg, r.Kid, want)
			}
		}
	}
}

func TestTheStoreSurvivesAReopenWithTheSameKeys(t *testing.T) {
	dir, c := dataDir(t), &clock{t0}
	first := open(t, dir, rootA, declared, c)
	kids := map[string]string{}
	for _, k := range declared {
		kids[k.Name] = activeKid(t, first, k.Name)
	}
	second := open(t, dir, rootA, declared, c)
	for _, k := range declared {
		if got := activeKid(t, second, k.Name); got != kids[k.Name] {
			t.Fatalf("%s: a reopen made a new key %s where %s was", k.Name, got, kids[k.Name])
		}
		sig, err := second.Sign(k.Name, []byte("after a restart"))
		if err != nil || sig.Kid != kids[k.Name] {
			t.Fatalf("%s: %v %s", k.Name, err, sig.Kid)
		}
	}
}

func TestAWrappedKeyOpensOnlyUnderItsOwnRootAndName(t *testing.T) {
	dir, c := dataDir(t), &clock{t0}
	open(t, dir, rootA, declared, c)
	if _, err := Open(dir, rootB, declared, c.Now); err == nil {
		t.Fatal("the store opened under another root key")
	}
	// Move approval's record under another name, and say so inside the record:
	// a wrap that was not bound to the name would open there and sign as it.
	open(t, dir, rootA, declared, c) // control: still opens under its own root
	files := recordFiles(t, dir)
	var src string
	for _, f := range files {
		if strings.Contains(f, string(filepath.Separator)+"approval"+string(filepath.Separator)) {
			src = f
		}
	}
	if src == "" {
		t.Fatal("no record for approval on disk")
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	rec["name"] = "impostor"
	moved, _ := json.Marshal(rec)
	dst := filepath.Join(dir, "keys", "impostor")
	if err := os.MkdirAll(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, filepath.Base(src)), moved, 0o600); err != nil {
		t.Fatal(err)
	}
	withImpostor := append(append([]policy.Key{}, declared...), policy.Key{Name: "impostor", Alg: policy.ES256})
	if _, err := Open(dir, rootA, withImpostor, c.Now); err == nil {
		t.Fatal("a key wrapped for one name opened under another")
	}
}

func TestATamperedRecordRefusesToOpen(t *testing.T) {
	c := &clock{t0}
	edits := map[string]func(map[string]any){
		"the public key swapped": func(r map[string]any) {
			r["public"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 65))
		},
		"the kid changed":        func(r map[string]any) { r["kid"] = "not-the-thumbprint" },
		"the algorithm changed":  func(r map[string]any) { r["alg"] = "ES384" },
		"an unknown algorithm":   func(r map[string]any) { r["alg"] = "HS256" },
		"an unknown state":       func(r map[string]any) { r["state"] = "dormant" },
		"an unknown field":       func(r map[string]any) { r["private"] = "here" },
		"a version from later":   func(r map[string]any) { r["v"] = 2 },
		"the wrapped bytes cut":  func(r map[string]any) { r["wrapped"] = r["wrapped"].(string)[:10] },
		"the nonce changed":      func(r map[string]any) { r["nonce"] = base64.RawURLEncoding.EncodeToString(make([]byte, 12)) },
		"the wrapped bytes gone": func(r map[string]any) { delete(r, "wrapped") },
		"the name gone":          func(r map[string]any) { delete(r, "name") },
	}
	for what, edit := range edits {
		dir := dataDir(t)
		open(t, dir, rootA, declared[:1], c)
		f := recordFiles(t, dir)[0]
		raw, _ := os.ReadFile(f)
		var rec map[string]any
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatal(err)
		}
		edit(rec)
		b, _ := json.Marshal(rec)
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dir, rootA, declared[:1], c.Now); err == nil {
			t.Errorf("%s: the store opened", what)
		}
	}
	// Two active keys for one name: a store that picked either would sign with
	// a key nobody can say was the current one.
	dir := dataDir(t)
	s := open(t, dir, rootA, declared[:1], c)
	if _, err := s.Rotate("approval", time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, f := range recordFiles(t, dir) {
		raw, _ := os.ReadFile(f)
		var rec map[string]any
		_ = json.Unmarshal(raw, &rec)
		rec["state"] = "active"
		b, _ := json.Marshal(rec)
		_ = os.WriteFile(f, b, 0o600)
	}
	if _, err := Open(dir, rootA, declared[:1], c.Now); err == nil {
		t.Error("two active keys for one name: the store opened")
	}
}

// Random damage to a stored record either refuses the open or leaves a store
// whose signature verifies with the key it publishes; nothing panics.
func TestHostileRecordFilesNeverPanicAndNeverSignWithAnUnpublishedKey(t *testing.T) {
	c := &clock{t0}
	base := dataDir(t)
	open(t, base, rootA, declared[:1], c)
	f := recordFiles(t, base)[0]
	orig, _ := os.ReadFile(f)
	r := rand.New(rand.NewPCG(20261018, 3))
	alphabet := []byte(`{}[]",:0123456789abcdefABCDEF-_ ` + "\x00\xff\n")
	opened := 0
	for i := 0; i < 1500; i++ {
		b := append([]byte(nil), orig...)
		for k := 0; k <= r.IntN(4); k++ {
			j := r.IntN(len(b))
			switch r.IntN(3) {
			case 0:
				b[j] = alphabet[r.IntN(len(alphabet))]
			case 1:
				b = append(b[:j], b[j+1:]...)
			default:
				b = append(b[:j], append([]byte{alphabet[r.IntN(len(alphabet))]}, b[j:]...)...)
			}
		}
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := Open(base, rootA, declared[:1], c.Now)
		if err != nil {
			continue
		}
		opened++
		recs, _ := s.Published("approval")
		sig, err := s.Sign("approval", []byte("x"))
		if err != nil {
			continue
		}
		published := false
		for _, rec := range recs {
			if rec.Kid == sig.Kid && bytes.Equal(rec.Public, sig.Public) && rec.State == Active {
				published = true
			}
		}
		if !published || Verify(sig.Alg, sig.Public, []byte("x"), sig.Sig) != nil {
			t.Fatalf("case %d: signed with a key that is not the one published", i)
		}
		// Put the original back so the next case starts from a real record.
		_ = os.WriteFile(f, orig, 0o600)
	}
	if err := os.WriteFile(f, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(base, rootA, declared[:1], c.Now); err != nil {
		t.Fatalf("control: the undamaged record no longer opens: %v", err)
	}
	t.Logf("%d of 1500 damaged records opened (whitespace and the like), every one consistent", opened)
}

func TestRotationPublishesTheNextKeyBeforeItSigns(t *testing.T) {
	dir, c := dataDir(t), &clock{t0}
	s := open(t, dir, rootA, declared, c)
	old := activeKid(t, s, "root")
	next, err := s.Rotate("root", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if next.State != Next || next.Kid == old {
		t.Fatalf("rotate returned %+v", next)
	}
	recs, _ := s.Published("root")
	if len(recs) != 2 {
		t.Fatalf("during the overlap the key set holds %d keys, want 2", len(recs))
	}
	if sig, _ := s.Sign("root", []byte("x")); sig.Kid != old {
		t.Fatalf("signed with %s before the verifiers could have seen it", sig.Kid)
	}
	c.now = t0.Add(15*time.Minute + time.Second)
	if sig, _ := s.Sign("root", []byte("x")); sig.Kid != next.Kid {
		t.Fatalf("after the overlap signed with %s, want %s", sig.Kid, next.Kid)
	}
	recs, _ = s.Published("root")
	states := map[string]State{}
	for _, r := range recs {
		states[r.Kid] = r.State
	}
	if states[old] != Retired || states[next.Kid] != Active {
		t.Fatalf("after the switch: %v", states)
	}
	// And a restart keeps that.
	again := open(t, dir, rootA, declared, c)
	if got := activeKid(t, again, "root"); got != next.Kid {
		t.Fatalf("after a restart the active key is %s", got)
	}
}

func TestASecondRotationWhileOneIsPendingIsRefused(t *testing.T) {
	s := open(t, dataDir(t), rootA, declared, &clock{t0})
	if _, err := s.Rotate("approval", time.Hour); err != nil {
		t.Fatalf("control: %v", err)
	}
	if _, err := s.Rotate("approval", time.Hour); !errors.Is(err, ErrRotationInProgress) {
		t.Fatalf("a second rotation: %v", err)
	}
	if _, err := s.Rotate("nope", time.Hour); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("rotating a key nobody declared: %v", err)
	}
}

func TestARevokedKeyIsNeverPublishedAndNeverSigns(t *testing.T) {
	dir, c := dataDir(t), &clock{t0}
	s := open(t, dir, rootA, declared, c)
	first := activeKid(t, s, "approval")
	next, _ := s.Rotate("approval", time.Hour)

	// Revoking the active key promotes the next one at once.
	if _, err := s.Revoke(first); err != nil {
		t.Fatal(err)
	}
	if sig, _ := s.Sign("approval", []byte("x")); sig.Kid != next.Kid {
		t.Fatalf("after revoking the active key, signed with %s", sig.Kid)
	}
	for _, r := range mustPublished(t, s, "approval") {
		if r.Kid == first {
			t.Fatal("a revoked key is still in the key set")
		}
	}
	// Revoking the only key left makes a fresh one rather than signing with nothing.
	if _, err := s.Revoke(next.Kid); err != nil {
		t.Fatal(err)
	}
	fresh := activeKid(t, s, "approval")
	if fresh == first || fresh == next.Kid {
		t.Fatalf("no fresh key after the last one was revoked: %s", fresh)
	}
	for _, r := range mustPublished(t, s, "approval") {
		if r.Kid == first || r.Kid == next.Kid {
			t.Fatalf("a revoked key is published: %+v", r)
		}
	}
	// And a restart does not bring either back.
	again := open(t, dir, rootA, declared, c)
	for _, r := range mustPublished(t, again, "approval") {
		if r.Kid == first || r.Kid == next.Kid {
			t.Fatalf("a revoked key came back after a restart: %+v", r)
		}
	}
	if _, err := s.Revoke("no-such-kid"); !errors.Is(err, ErrUnknownKid) {
		t.Fatalf("revoking an unknown kid: %v", err)
	}
	// The inventory still says what was revoked: the record of a revocation
	// is not the key set.
	n := 0
	for _, r := range again.Inventory() {
		if r.State == Revoked {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("the inventory names %d revoked keys, want 2", n)
	}
}

func mustPublished(t *testing.T, s *Store, name string) []Record {
	t.Helper()
	recs, ok := s.Published(name)
	if !ok || len(recs) == 0 {
		t.Fatalf("%s publishes nothing", name)
	}
	return recs
}

func TestTheStoreNeverWritesAPrivateKeyInTheClear(t *testing.T) {
	dir, c := dataDir(t), &clock{t0}
	s := open(t, dir, rootA, declared, c)
	for _, k := range declared {
		if _, err := s.Rotate(k.Name, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	secrets := s.privateMaterial()
	if len(secrets) < 2*len(declared) {
		t.Fatalf("the store reports %d private encodings for %d keys, so this test measured nothing", len(secrets), 2*len(declared))
	}
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, sec := range secrets {
			for _, form := range [][]byte{sec, []byte(base64.StdEncoding.EncodeToString(sec)), []byte(base64.RawURLEncoding.EncodeToString(sec))} {
				if bytes.Contains(raw, form) {
					t.Errorf("%s holds a private key in the clear", p)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAStatementOverTheCapOrEmptyIsRefused(t *testing.T) {
	s := open(t, dataDir(t), rootA, declared, &clock{t0})
	if _, err := s.Sign("approval", bytes.Repeat([]byte("x"), MaxStatement)); err != nil {
		t.Fatalf("control: a statement at the cap was refused: %v", err)
	}
	if _, err := s.Sign("approval", bytes.Repeat([]byte("x"), MaxStatement+1)); !errors.Is(err, ErrStatementTooLarge) {
		t.Fatalf("a statement over the cap: %v", err)
	}
	if _, err := s.Sign("approval", nil); err == nil {
		t.Fatal("an empty statement was signed")
	}
}

func TestADataDirectoryOpenToGroupOrOtherIsRefused(t *testing.T) {
	c := &clock{t0}
	if _, err := Open(dataDir(t), rootA, declared, c.Now); err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, mode := range []os.FileMode{0o750, 0o705, 0o770, 0o755, 0o777} {
		d := dataDir(t)
		if err := os.Chmod(d, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(d, rootA, declared, c.Now); err == nil {
			t.Errorf("a data directory with mode %o was accepted", mode)
		}
	}
	if _, err := Open(filepath.Join(t.TempDir(), "absent"), rootA, declared, c.Now); err == nil {
		t.Error("a missing data directory was accepted")
	}
}

func TestTheJWKCarriesNoPrivateMember(t *testing.T) {
	s := open(t, dataDir(t), rootA, declared, &clock{t0})
	allowed := map[string]bool{"kty": true, "crv": true, "x": true, "y": true, "kid": true, "alg": true, "use": true, "pub": true}
	for _, k := range declared {
		for _, r := range mustPublished(t, s, k.Name) {
			j := JWK(r)
			if len(j) == 0 {
				t.Fatalf("%s: no JWK", k.Name)
			}
			for member := range j {
				if !allowed[member] {
					t.Errorf("%s: the JWK carries %q", k.Name, member)
				}
			}
			if j["kid"] != r.Kid {
				t.Errorf("%s: JWK kid %v, record kid %s", k.Name, j["kid"], r.Kid)
			}
		}
	}
}

func TestAnUndeclaredKeyOnDiskIsPublishedAndNeverSigns(t *testing.T) {
	dir, c := dataDir(t), &clock{t0}
	open(t, dir, rootA, declared, c)
	s := open(t, dir, rootA, declared[1:], c) // "approval" no longer declared
	if _, err := s.Sign("approval", []byte("x")); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("a key the policy no longer declares signed: %v", err)
	}
	if recs, ok := s.Published("approval"); !ok || len(recs) == 0 {
		t.Fatal("a key that signed evidence before stopped being published, so its evidence stops verifying")
	}
}

var _ = ecdsa.PublicKey{}
