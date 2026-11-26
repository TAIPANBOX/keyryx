package keystore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/policy"
)

// The store refuses a data directory it cannot call its own, and the
// statement path signs only what it can stand behind.

func TestOpenRefusesADataDirectoryItCannotCallItsOwn(t *testing.T) {
	c := &clock{now: t0}
	base := t.TempDir()
	file := filepath.Join(base, "file")
	_ = os.WriteFile(file, nil, 0o600)
	open := filepath.Join(base, "open")
	_ = os.Mkdir(open, 0o700)
	_ = os.Chmod(open, 0o750)
	for name, tc := range map[string]struct {
		dir  string
		root [32]byte
		want string
	}{
		"a directory that is not there":  {filepath.Join(base, "gone"), rootA, "the data directory"},
		"a file":                         {file, rootA, "is not a directory"},
		"a directory its group can read": {open, rootA, "open to group or other"},
		"an all-zero root key":           {dataDir(t), [32]byte{}, "all zero"},
	} {
		if s, err := Open(tc.dir, tc.root, declared, c.Now); err == nil || s != nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, plant := range map[string]func(keys string){
		"a file among the key directories": func(keys string) { _ = os.WriteFile(filepath.Join(keys, "approval"), nil, 0o600) },
		"a directory no key is named":      func(keys string) { _ = os.Mkdir(filepath.Join(keys, "Not A Name"), 0o700) },
	} {
		dir := dataDir(t)
		keys := filepath.Join(dir, "keys")
		_ = os.Mkdir(keys, 0o700)
		plant(keys)
		if _, err := Open(dir, rootA, declared, c.Now); err == nil || !strings.Contains(err.Error(), "not a key directory") {
			t.Errorf("%s: %v", name, err)
		}
	}
	dir := dataDir(t)
	_ = os.WriteFile(filepath.Join(dir, "keys"), nil, 0o600)
	if _, err := Open(dir, rootA, declared, c.Now); err == nil || !strings.Contains(err.Error(), "creating") {
		t.Errorf("a file where the key directories go: %v", err)
	}
}

func TestAKeyWhoseDeclaredAlgorithmChangedRefusesTheStart(t *testing.T) {
	c := &clock{now: t0}
	dir := dataDir(t)
	open(t, dir, rootA, declared, c)
	changed := []policy.Key{{Name: "approval", Alg: policy.ES384}}
	if _, err := Open(dir, rootA, changed, c.Now); err == nil || !strings.Contains(err.Error(), "declares approval as ES384") {
		t.Fatalf("a key held as ES256 and declared ES384: %v", err)
	}
}

func TestAWriteThatDiedBeforeItsRenameIsNotARecord(t *testing.T) {
	c := &clock{now: t0}
	dir := dataDir(t)
	kid := activeKid(t, open(t, dir, rootA, declared, c), "approval")
	_ = os.WriteFile(filepath.Join(dir, "keys", "approval", ".tmp-123"), []byte("half a record"), 0o600)
	s, err := Open(dir, rootA, declared, c.Now)
	if err != nil {
		t.Fatalf("a temporary file refused the start: %v", err)
	}
	if got := activeKid(t, s, "approval"); got != kid {
		t.Fatalf("the active key changed over a temporary file: %s, was %s", got, kid)
	}
}

func TestAStateMACBindsItsKindItsFieldsTheirBoundsAndItsRoot(t *testing.T) {
	c := &clock{now: t0}
	a := open(t, dataDir(t), rootA, declared, c)
	b := open(t, dataDir(t), rootB, declared, c)
	mac := a.StateMAC("statement", "kid-1", "active", "0")
	if len(mac) != 32 || !a.StateMACValid(mac, "statement", "kid-1", "active", "0") {
		t.Fatalf("a MAC does not hold over what it was made of: %x", mac)
	}
	for name, ok := range map[string]bool{
		"another kind":       a.StateMACValid(mac, "retired", "kid-1", "active", "0"),
		"another field":      a.StateMACValid(mac, "statement", "kid-1", "revoked", "0"),
		"a moved boundary":   a.StateMACValid(mac, "statement", "kid-1a", "ctive", "0"),
		"a field fewer":      a.StateMACValid(mac, "statement", "kid-1", "active"),
		"another root's key": b.StateMACValid(mac, "statement", "kid-1", "active", "0"),
		"a truncated MAC":    a.StateMACValid(mac[:16], "statement", "kid-1", "active", "0"),
	} {
		if ok {
			t.Errorf("%s: the MAC held", name)
		}
	}
}

func TestTheStatementPathSignsOnlyWhatItCanStandBehind(t *testing.T) {
	c := &clock{now: t0}
	s := open(t, dataDir(t), rootA, declared, c)
	never := func(policy.Alg, string) ([]byte, error) { t.Fatal("build ran for an undeclared name"); return nil, nil }
	if _, err := s.SignInput("undeclared", never); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("an undeclared name: %v", err)
	}
	boom := errors.New("the statement does not build")
	if _, err := s.SignInput("approval", func(policy.Alg, string) ([]byte, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("a build that failed: %v", err)
	}
	for size, want := range map[int]error{0: ErrEmptyStatement, MaxStatement + 1: ErrStatementTooLarge} {
		if _, err := s.SignInput("approval", func(policy.Alg, string) ([]byte, error) { return make([]byte, size), nil }); !errors.Is(err, want) {
			t.Errorf("a statement of %d bytes: %v, want %v", size, err, want)
		}
	}
	kid := activeKid(t, s, "approval")
	var sawAlg policy.Alg
	var sawKid string
	in := bytes.Repeat([]byte("s"), MaxStatement)
	sig, err := s.SignInput("approval", func(alg policy.Alg, k string) ([]byte, error) { sawAlg, sawKid = alg, k; return in, nil })
	if err != nil {
		t.Fatalf("a statement at the cap: %v", err)
	}
	if sawAlg != policy.ES256 || sawKid != kid || sig.Kid != kid || sig.Alg != policy.ES256 {
		t.Fatalf("build saw %s %s, the signature names %s %s, the active key is %s", sawAlg, sawKid, sig.Alg, sig.Kid, kid)
	}
	if err := Verify(sig.Alg, sig.Public, in, sig.Sig); err != nil {
		t.Fatalf("the signature does not verify: %v", err)
	}
	if _, ok := s.Active("undeclared"); ok {
		t.Fatal("an undeclared name has an active key")
	}
}

func TestRotateAndRevokeRefuseWhatTheyDoNotKnowAndARevocationStandsOnce(t *testing.T) {
	c := &clock{now: t0}
	s := open(t, dataDir(t), rootA, declared, c)
	if _, err := s.Rotate("undeclared", time.Minute); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("rotating an undeclared name: %v", err)
	}
	if _, err := s.Revoke("no-such-kid"); !errors.Is(err, ErrUnknownKid) {
		t.Fatalf("revoking an unknown kid: %v", err)
	}
	kid := activeKid(t, s, "approval")
	first, err := s.Revoke(kid)
	if err != nil || first.State != Revoked || first.Revoked != t0.Unix() {
		t.Fatalf("a revocation: %+v %v", first, err)
	}
	c.now = t0.Add(time.Hour)
	again, err := s.Revoke(kid)
	if err != nil || again.Revoked != first.Revoked {
		t.Fatalf("a second revocation moved the time it was revoked: %+v %v", again, err)
	}
	if got := activeKid(t, s, "approval"); got == kid {
		t.Fatal("the revoked key is still active")
	}
}
