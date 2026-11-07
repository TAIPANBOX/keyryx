package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/statement"
	"github.com/TAIPANBOX/keyryx/internal/witness"
)

const threeDays = 72 * 3600

// start has one key certified for vouchryx through the routes, an hour after
// the one before, as one more start of that consumer would.
func (s *stand) start(t *testing.T) ownKey {
	t.Helper()
	s.now = s.now.Add(time.Hour)
	k := newOwnKey(t)
	c := s.challenge(t, "vouchryx-token", "", vouchryxSecret)
	w, _ := s.do(t, "POST", "/v1/keys/vouchryx-token/delegate", delegateBody(t, k, "vouchryx-token", "vouchryx", c, threeDays), "", vouchryxSecret)
	if w.Code != http.StatusOK {
		t.Fatalf("a start: %d %s", w.Code, w.Body)
	}
	return k
}

func TestARetirementIsOnTheUseLogAndTheInventoryNamesIt(t *testing.T) {
	s := newDelegationStand(t)
	old := s.start(t)
	for i := 0; i < 3; i++ {
		s.start(t)
	}
	fifth := s.start(t)
	if kids := s.jwksKids(t, "vouchryx-token"); kids[old.kid] || !kids[fifth.kid] || len(kids) != 4 {
		t.Fatalf("the key set: %v", kids)
	}
	lines := s.logLines(t)
	if len(lines) != 6 {
		t.Fatalf("%d lines on the use log, want five delegations and one retirement: %v", len(lines), lines)
	}
	retire, delegate := lines[4], lines[5]
	if !strings.Contains(retire, `"op":"retire"`) || !strings.Contains(retire, `"kid":"`+old.kid+`"`) ||
		!strings.Contains(retire, `"consumer":"vouchryx"`) || !strings.Contains(retire, `"key":"vouchryx-token"`) {
		t.Fatalf("the retirement line: %s", retire)
	}
	if !strings.Contains(delegate, `"op":"delegate"`) || !strings.Contains(delegate, `"kid":"`+fifth.kid+`"`) {
		t.Fatalf("the line after it: %s", delegate)
	}
	w, _ := s.do(t, "GET", "/v1/keys", "", "", adminSecret)
	if w.Code != http.StatusOK {
		t.Fatalf("inventory: %d %s", w.Code, w.Body)
	}
	var inv struct {
		Keys []struct {
			Kid     string `json:"kid"`
			State   string `json:"state"`
			Retired int64  `json:"retired"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &inv); err != nil {
		t.Fatal(err)
	}
	states := map[string]int{}
	for _, k := range inv.Keys {
		switch k.Kid {
		case old.kid:
			if k.State != "retired" || k.Retired != s.now.Unix() {
				t.Fatalf("the retired key reads %+v", k)
			}
		default:
			states[k.State]++
		}
	}
	if states["retired"] != 0 {
		t.Fatalf("other keys read retired: %v", states)
	}
}

func TestACheckpointSignedBeforeItsKeyRetiredStillVerifiesAtTheWitness(t *testing.T) {
	s := newDelegationStand(t)
	old := s.start(t)
	signed := s.now.Add(time.Minute)
	for i := 0; i < 4; i++ {
		s.start(t)
	}
	if s.jwksKids(t, "vouchryx-token")[old.kid] {
		t.Fatal("control: the oldest key is still published")
	}
	w, _ := s.do(t, "GET", "/v1/statements/"+old.kid, "", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("the statement of a retired key: %d", w.Code)
	}
	raw, revoked, err := witness.ParseStatementAnswer(w.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := witness.KeyFromStatement(raw, revoked, statement.StoreRoots(s.srv.Store), old.kid, signed, s.now); err != nil {
		t.Fatalf("the witness refused a record signed before the key retired: %v", err)
	}
}
