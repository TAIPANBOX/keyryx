package certify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A statement's revoked state is what takes a stolen delegated key out of
// every key set; a writer of the data directory who could clear it would put
// the key back.

func statementFile(t *testing.T, dir, kid string) (string, map[string]any) {
	t.Helper()
	for _, f := range statementFiles(t, dir) {
		if filepath.Base(f) == kid+".json" {
			raw, _ := os.ReadFile(f)
			var r map[string]any
			if err := json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			return f, r
		}
	}
	t.Fatalf("no statement file for %s", kid)
	return "", nil
}

func writeJSON(t *testing.T, path string, r map[string]any) {
	t.Helper()
	b, _ := json.Marshal(r)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (s *stand) alarmFor(kid string) bool {
	for _, a := range s.reg.Alarms() {
		if a.Kid == kid && a.Kind == "statement" && a.Name != "" && a.Reason != "" {
			return true
		}
	}
	return false
}

func TestAnEditedStatementStateIsTreatedAsRevokedAndRaisesAnAlarm(t *testing.T) {
	setup := func() (*stand, holder, holder) {
		s := newStand(t)
		a, b := newHolder(t), newHolder(t)
		for _, h := range []holder{a, b} {
			if _, _, err := s.certify(h, "vouchryx", "vouchryx-token", time.Hour); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.reg.Revoke(a.kid); err != nil {
			t.Fatal(err)
		}
		return s, a, b
	}
	s, a, b := setup()
	s.reopen()
	if len(s.reg.Alarms()) != 0 || s.published("vouchryx-token")[a.kid] || !s.published("vouchryx-token")[b.kid] {
		t.Fatalf("control: alarms %v, published %v", s.reg.Alarms(), s.published("vouchryx-token"))
	}
	for what, c := range map[string]struct {
		target func(a, b holder) holder
		edit   func(s *stand, a, b holder, r map[string]any)
	}{
		"a revoked statement edited back": {func(a, _ holder) holder { return a }, func(_ *stand, _, _ holder, r map[string]any) { r["revoked"] = 0 }},
		"the revocation time moved":       {func(a, _ holder) holder { return a }, func(_ *stand, _, _ holder, r map[string]any) { r["revoked"] = t0.Add(time.Hour).Unix() }},
		"a live statement given a MAC of another": {func(_, b holder) holder { return b }, func(s *stand, a, _ holder, r map[string]any) {
			_, other := statementFile(t, s.dir, a.kid)
			r["mac"] = other["mac"]
		}},
		"the revoked one given the live one's MAC": {func(a, _ holder) holder { return a }, func(s *stand, _, b holder, r map[string]any) {
			_, other := statementFile(t, s.dir, b.kid)
			r["mac"], r["revoked"] = other["mac"], 0
		}},
		"the MAC removed":                {func(_, b holder) holder { return b }, func(_ *stand, _, _ holder, r map[string]any) { delete(r, "mac") }},
		"a version 1 record with no MAC": {func(_, b holder) holder { return b }, func(_ *stand, _, _ holder, r map[string]any) { r["v"] = 1; delete(r, "mac") }},
	} {
		s, a, b := setup()
		h := c.target(a, b)
		path, r := statementFile(t, s.dir, h.kid)
		c.edit(s, a, b, r)
		writeJSON(t, path, r)
		reg, err := Open(s.dir, s.store, s.pol, ahead, s.clock)
		if err != nil {
			t.Errorf("%s: the registry refused to open (%v); an edited state is an alarm, not an outage", what, err)
			continue
		}
		s.reg = reg
		if s.published("vouchryx-token")[h.kid] {
			t.Errorf("%s: %s is published", what, h.kid)
		}
		if !s.alarmFor(h.kid) {
			t.Errorf("%s: no alarm names %s: %v", what, h.kid, reg.Alarms())
		}
		if _, rev, _ := reg.Statement(h.kid); rev == 0 {
			t.Errorf("%s: its statement reads as not revoked", what)
		}
	}
}

func TestRevokingAnAlarmedStatementAcknowledgesIt(t *testing.T) {
	s := newStand(t)
	h := newHolder(t)
	if _, _, err := s.certify(h, "vouchryx", "vouchryx-token", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.reg.Revoke(h.kid); err != nil {
		t.Fatal(err)
	}
	path, r := statementFile(t, s.dir, h.kid)
	r["revoked"] = 0
	writeJSON(t, path, r)
	s.reopen()
	if !s.alarmFor(h.kid) {
		t.Fatal("control: no alarm")
	}
	if _, err := s.reg.Revoke(h.kid); err != nil {
		t.Fatalf("revoking the alarmed statement: %v", err)
	}
	s.reopen()
	if s.alarmFor(h.kid) {
		t.Fatal("the alarm survived an operator's revocation")
	}
	if s.published("vouchryx-token")[h.kid] {
		t.Fatal("the acknowledged key is published")
	}
}
