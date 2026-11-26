package certify

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/statement"
)

// The inventory names every statement once, revoked ones included, in one
// order; a lookup of what was never certified answers nothing; challenges
// that expired are gone; and a statement directory custody never wrote
// refuses the open.

func TestTheInventoryListsEveryStatementByNameThenAgeThenKid(t *testing.T) {
	s := newStand(t)
	if inv := s.reg.Inventory(); len(inv) != 0 {
		t.Fatalf("a new registry lists %d statements", len(inv))
	}
	h1, h2, h3, h4 := newHolder(t), newHolder(t), newHolder(t), newHolder(t)
	for _, c := range []struct {
		h        holder
		consumer string
		name     string
	}{{h1, "vouchryx", "vouchryx-token"}, {h2, "wardryx", "wardryx-stream"}} {
		if _, _, err := s.certify(c.h, c.consumer, c.name, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	s.now = t0.Add(time.Minute)
	for _, h := range []holder{h3, h4} {
		if _, _, err := s.certify(h, "vouchryx", "vouchryx-token", time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	s.now = t0.Add(2 * time.Minute)
	if _, err := s.reg.Revoke(h1.kid); err != nil {
		t.Fatal(err)
	}
	later, earlier := h3.kid, h4.kid
	if earlier > later {
		earlier, later = later, earlier
	}
	want := []struct {
		name, kid string
		revoked   int64
	}{{"vouchryx-token", h1.kid, t0.Add(2 * time.Minute).Unix()}, {"vouchryx-token", earlier, 0}, {"vouchryx-token", later, 0}, {"wardryx-stream", h2.kid, 0}}
	inv := s.reg.Inventory()
	if len(inv) != len(want) {
		t.Fatalf("the inventory lists %d statements, want %d", len(inv), len(want))
	}
	for i, w := range want {
		e := inv[i]
		if e.Statement.Name != w.name || e.Statement.Kid != w.kid || e.Revoked != w.revoked || e.Retired != 0 {
			t.Errorf("entry %d: %s %s revoked %d retired %d, want %s %s revoked %d", i, e.Statement.Name, e.Statement.Kid, e.Revoked, e.Retired, w.name, w.kid, w.revoked)
		}
	}
}

func TestWhatWasNeverCertifiedAnswersNothingAndARevocationStandsOnce(t *testing.T) {
	s := newStand(t)
	h := newHolder(t)
	_, raw, err := s.certify(h, "vouchryx", "vouchryx-token", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got, rev, ok := s.reg.Statement("never-certified"); ok || got != nil || rev != 0 {
		t.Fatalf("an unknown kid: %q %d %v", got, rev, ok)
	}
	got, rev, ok := s.reg.Statement(h.kid)
	if !ok || string(got) != string(raw) || rev != 0 {
		t.Fatalf("a certified kid: %v %d, the statement %s", ok, rev, got)
	}
	got[0] ^= 0xff
	if again, _, _ := s.reg.Statement(h.kid); string(again) != string(raw) {
		t.Fatal("an edit of the statement handed out reached the registry")
	}
	if _, err := s.reg.Revoke("never-certified"); !errors.Is(err, ErrUnknownKid) {
		t.Fatalf("revoking an unknown kid: %v", err)
	}
	s.now = t0.Add(time.Minute)
	if _, err := s.reg.Revoke(h.kid); err != nil {
		t.Fatal(err)
	}
	s.now = t0.Add(time.Hour)
	if _, err := s.reg.Revoke(h.kid); err != nil {
		t.Fatalf("a second revocation: %v", err)
	}
	if _, rev, _ := s.reg.Statement(h.kid); rev != t0.Add(time.Minute).Unix() {
		t.Fatalf("a second revocation moved the time it was revoked to %d", rev)
	}
}

func TestAChallengeIsIssuedOnlyForADelegatedNameAndExpiredOnesAreGone(t *testing.T) {
	s := newStand(t)
	if _, _, err := s.reg.Challenge("wardryx", "wardryx-approval"); !errors.Is(err, ErrNotDelegated) {
		t.Fatalf("a challenge for a held key: %v", err)
	}
	if _, _, err := s.reg.Challenge("wardryx", "undeclared"); !errors.Is(err, ErrNotDelegated) {
		t.Fatalf("a challenge for an undeclared name: %v", err)
	}
	old, exp, err := s.reg.Challenge("vouchryx", "vouchryx-token")
	if err != nil || exp != t0.Add(ChallengeTTL).Unix() {
		t.Fatalf("a challenge: %v, expires %d", err, exp)
	}
	s.now = t0.Add(ChallengeTTL)
	if _, _, err := s.reg.Challenge("wardryx", "wardryx-stream"); err != nil {
		t.Fatal(err)
	}
	s.reg.mu.Lock()
	_, kept := s.reg.challenges[old]
	n := len(s.reg.challenges)
	s.reg.mu.Unlock()
	if kept || n != 1 {
		t.Fatalf("an expired challenge was kept (%v), %d outstanding", kept, n)
	}
	h := newHolder(t)
	_, _, err = s.reg.Delegate("vouchryx", "vouchryx-token", Request{JWK: h.jwk, Challenge: old, Proof: h.prove(t, "vouchryx-token", "vouchryx", old), Lifetime: time.Hour}, record, recordRetired)
	if !errors.Is(err, ErrNoChallenge) {
		t.Fatalf("an expired challenge answered: %v", err)
	}
}

func TestAStatementDirectoryCustodyNeverWroteRefusesTheOpen(t *testing.T) {
	for name, tc := range map[string]struct {
		plant func(dir string)
		want  string
	}{
		"a file where the statements go": {func(dir string) { _ = os.WriteFile(filepath.Join(dir, "statements"), nil, 0o600) }, "creating"},
		"a file among the names": {func(dir string) {
			_ = os.MkdirAll(filepath.Join(dir, "statements"), 0o700)
			_ = os.WriteFile(filepath.Join(dir, "statements", "vouchryx-token"), nil, 0o600)
		}, "not a statement directory"},
		"a directory no name is": {func(dir string) { _ = os.MkdirAll(filepath.Join(dir, "statements", "Not A Name"), 0o700) }, "not a statement directory"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "data")
			_ = os.Mkdir(dir, 0o700)
			pol := testPolicy(t)
			store, err := keystore.Open(dir, [32]byte{5, 4, 3, 2, 1}, append(pol.HeldKeys(), statement.RootKeys...), func() time.Time { return t0 })
			if err != nil {
				t.Fatal(err)
			}
			tc.plant(dir)
			if r, err := Open(dir, store, pol, ahead, func() time.Time { return t0 }); err == nil || r != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%v, want it to say %q", err, tc.want)
			}
		})
	}
}

func TestAWriteThatDiedBeforeItsRenameIsNotAStatement(t *testing.T) {
	s := newStand(t)
	h := newHolder(t)
	if _, _, err := s.certify(h, "vouchryx", "vouchryx-token", time.Hour); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(s.dir, "statements", "vouchryx-token", ".tmp-1"), []byte("half"), 0o600)
	s.reopen()
	if inv := s.reg.Inventory(); len(inv) != 1 || inv[0].Statement.Kid != h.kid {
		t.Fatalf("after a reopen over a temporary file: %+v", inv)
	}
}
