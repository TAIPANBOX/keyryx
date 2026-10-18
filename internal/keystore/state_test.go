package keystore

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// A key's state is what decides whether it is published and whether it
// signs. A writer of the data directory who could edit it could take a
// revoked key back into every key set, and nothing would say so.

// recordOf reads the record file of kid.
func recordOf(t *testing.T, dir, kid string) (string, map[string]any) {
	t.Helper()
	for _, f := range recordFiles(t, dir) {
		if strings.HasSuffix(f, fileName(kid)) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var r map[string]any
			if err := json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			return f, r
		}
	}
	t.Fatalf("no record file for %s", kid)
	return "", nil
}

func writeRecord(t *testing.T, path string, r map[string]any) {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func published(s *Store, name string) map[string]bool {
	recs, _ := s.Published(name)
	out := map[string]bool{}
	for _, r := range recs {
		out[r.Kid] = true
	}
	return out
}

func alarmed(s *Store, kid string) (Alarm, bool) {
	for _, a := range s.Alarms() {
		if a.Kid == kid {
			return a, true
		}
	}
	return Alarm{}, false
}

// aRevokedKey makes a store holding approval's revoked first key, its active
// second key, and returns the store's directory and the two kids.
func aRevokedKey(t *testing.T, c *clock) (dir, revoked, active string) {
	t.Helper()
	dir = dataDir(t)
	s := open(t, dir, rootA, declared[:1], c)
	revoked = activeKid(t, s, "approval")
	next, err := s.Rotate("approval", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Revoke(revoked); err != nil {
		t.Fatal(err)
	}
	return dir, revoked, next.Kid
}

func TestAnEditedKeyStateIsTreatedAsRevokedAndRaisesAnAlarm(t *testing.T) {
	c := &clock{t0}
	// Control: an honest reopen raises nothing.
	dir, revoked, active := aRevokedKey(t, c)
	s := open(t, dir, rootA, declared[:1], c)
	if len(s.Alarms()) != 0 || published(s, "approval")[revoked] || !published(s, "approval")[active] {
		t.Fatalf("control: alarms %v, published %v", s.Alarms(), published(s, "approval"))
	}
	other := func(dir, active string) string { // a MAC from another record of the same store
		_, r := recordOf(t, dir, active)
		m, _ := r["mac"].(string)
		return m
	}
	for what, c2 := range map[string]struct {
		kid  func(revoked, active string) string
		edit func(dir, active string, r map[string]any)
	}{
		"a revoked key edited back to retired": {func(r, _ string) string { return r }, func(_, _ string, r map[string]any) {
			r["state"], r["revoked"], r["retired"] = "retired", 0, t0.Unix()
		}},
		"a revoked key edited back to active, the active one to retired": {func(r, _ string) string { return r }, func(_, _ string, r map[string]any) {
			r["state"], r["revoked"] = "active", 0
		}},
		"the revocation time moved":       {func(r, _ string) string { return r }, func(_, _ string, r map[string]any) { r["revoked"] = t0.Add(time.Hour).Unix() }},
		"the creation time moved":         {func(_, a string) string { return a }, func(_, _ string, r map[string]any) { r["created"] = t0.Add(-time.Hour).Unix() }},
		"the activation time moved":       {func(_, a string) string { return a }, func(_, _ string, r map[string]any) { r["activate_at"] = t0.Add(time.Hour).Unix() }},
		"the retirement time moved":       {func(_, a string) string { return a }, func(_, _ string, r map[string]any) { r["retired"] = t0.Unix() }},
		"the MAC removed":                 {func(_, a string) string { return a }, func(_, _ string, r map[string]any) { delete(r, "mac") }},
		"the MAC not base64url":           {func(_, a string) string { return a }, func(_, _ string, r map[string]any) { r["mac"] = "***" }},
		"the MAC of another record":       {func(r, _ string) string { return r }, func(dir, active string, r map[string]any) { r["mac"] = other(dir, active) }},
		"a version 1 record with no MAC":  {func(_, a string) string { return a }, func(_, _ string, r map[string]any) { r["v"] = 1; delete(r, "mac") }},
		"a version 1 record with its MAC": {func(_, a string) string { return a }, func(_, _ string, r map[string]any) { r["v"] = 1 }},
	} {
		dir, revoked, active := aRevokedKey(t, c)
		kid := c2.kid(revoked, active)
		path, r := recordOf(t, dir, kid)
		c2.edit(dir, active, r)
		writeRecord(t, path, r)
		s, err := Open(dir, rootA, declared[:1], c.Now)
		if err != nil {
			t.Errorf("%s: the store refused to open (%v); an edited state is an alarm, not an outage", what, err)
			continue
		}
		if published(s, "approval")[kid] {
			t.Errorf("%s: %s is published", what, kid)
		}
		if sig, err := s.Sign("approval", []byte("x")); err != nil || sig.Kid == kid {
			t.Errorf("%s: signed with %s (%v)", what, sig.Kid, err)
		}
		if a, ok := alarmed(s, kid); !ok || a.Kind != "key" || a.Name != "approval" || a.Reason == "" {
			t.Errorf("%s: no alarm names %s: %v", what, kid, s.Alarms())
		}
		for _, rec := range s.Inventory() {
			if rec.Kid == kid && rec.State != Revoked {
				t.Errorf("%s: the inventory says %s is %s", what, kid, rec.State)
			}
		}
	}
}

func TestAnEditedActiveKeyIsReplacedNotUsed(t *testing.T) {
	c := &clock{t0}
	dir := dataDir(t)
	s := open(t, dir, rootA, declared[:1], c)
	old := activeKid(t, s, "approval")
	path, r := recordOf(t, dir, old)
	r["created"] = t0.Add(-24 * time.Hour).Unix()
	writeRecord(t, path, r)
	s2, err := Open(dir, rootA, declared[:1], c.Now)
	if err != nil {
		t.Fatalf("an edited active key stopped the store: %v", err)
	}
	fresh := activeKid(t, s2, "approval")
	if fresh == old {
		t.Fatal("the key whose state was edited is still the active one")
	}
	if sig, err := s2.Sign("approval", []byte("x")); err != nil || sig.Kid != fresh {
		t.Fatalf("signed with %s (%v), want the fresh key %s", sig.Kid, err, fresh)
	}
	if _, ok := alarmed(s2, old); !ok {
		t.Fatalf("no alarm names the edited key: %v", s2.Alarms())
	}
	// The edited record is evidence and stays as it was found.
	after, _ := os.ReadFile(path)
	want, _ := json.Marshal(r)
	if string(after) != string(want) {
		t.Fatal("the store rewrote the record it raised an alarm about")
	}
}

func TestRevokingAnAlarmedKeyAcknowledgesIt(t *testing.T) {
	c := &clock{t0}
	dir, revoked, _ := aRevokedKey(t, c)
	path, r := recordOf(t, dir, revoked)
	r["state"], r["revoked"] = "retired", 0
	writeRecord(t, path, r)
	s := open(t, dir, rootA, declared[:1], c)
	if _, ok := alarmed(s, revoked); !ok {
		t.Fatal("control: no alarm")
	}
	if _, err := s.Revoke(revoked); err != nil {
		t.Fatalf("revoking the alarmed key: %v", err)
	}
	s2 := open(t, dir, rootA, declared[:1], c)
	if _, ok := alarmed(s2, revoked); ok {
		t.Fatal("the alarm survived an operator's revocation of the key")
	}
	if published(s2, "approval")[revoked] {
		t.Fatal("the acknowledged key is published")
	}
}

func TestAStateMACMadeWithoutTheRootDoesNotHold(t *testing.T) {
	c := &clock{t0}
	dir, revoked, _ := aRevokedKey(t, c)
	path, r := recordOf(t, dir, revoked)
	r["state"], r["revoked"] = "retired", 0
	// Somebody who knows the format exactly and not the root key: the MAC is
	// the store's own message for the edited state, under a key derived from
	// no secret at all, or from an all-zero root.
	raw, _ := json.Marshal(r)
	var f recordFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	for what, root := range map[string][]byte{"a key from no secret": nil, "a key from a zero root": make([]byte, 32)} {
		key, err := hkdf.Key(sha512.New384, root, []byte(stateSalt), stateInfo, 32)
		if err != nil {
			t.Fatal(err)
		}
		mac := hmac.New(sha256.New, key)
		mac.Write(keyStateInput(f))
		r["mac"] = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		writeRecord(t, path, r)
		s := open(t, dir, rootA, declared[:1], c)
		if published(s, "approval")[revoked] {
			t.Errorf("%s: the revoked key is published", what)
		}
		if _, ok := alarmed(s, revoked); !ok {
			t.Errorf("%s: no alarm", what)
		}
	}
}
