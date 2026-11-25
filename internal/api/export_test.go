package api

import (
	"errors"
	"net/http"
	"testing"

	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/statement"
)

// What custody copies for a reader on the machine (invariant 44): a revocation
// and a change of the root are written as part of the admin change, a
// certification soon after its answer.

type fakeExporter struct {
	kids   []string
	roots  int
	marked []string
	fail   bool
}

func (f *fakeExporter) Kid(kid string) error {
	if f.fail {
		return errors.New("the directory takes nothing")
	}
	f.kids = append(f.kids, kid)
	return nil
}

func (f *fakeExporter) Root() error {
	if f.fail {
		return errors.New("the directory takes nothing")
	}
	f.roots++
	return nil
}

func (f *fakeExporter) Mark(kid string) { f.marked = append(f.marked, kid) }
func (f *fakeExporter) Unexported() int { return len(f.marked) }

func TestACertificationIsMarkedForTheReadersCopy(t *testing.T) {
	s := newDelegationStand(t)
	fx := &fakeExporter{}
	s.srv.Export = fx
	k := newOwnKey(t)
	c := s.challenge(t, "vouchryx-token", "", vouchryxSecret)
	if w, _ := s.do(t, "POST", "/v1/keys/vouchryx-token/delegate", delegateBody(t, k, "vouchryx-token", "vouchryx", c, 3600), "", vouchryxSecret); w.Code != http.StatusOK {
		t.Fatalf("delegate: %d", w.Code)
	}
	if len(fx.marked) != 1 || fx.marked[0] != k.kid || len(fx.kids) != 0 {
		t.Fatalf("a certification: marked %v, written now %v", fx.marked, fx.kids)
	}
	if _, body := s.do(t, "GET", "/v1/state", "", "", ""); body["unexported"] != float64(1) {
		t.Fatalf("the state route: %v", body["unexported"])
	}
}

func TestARevocationOfADelegatedKeyIsCopiedAsPartOfTheChange(t *testing.T) {
	s := newDelegationStand(t)
	fx := &fakeExporter{}
	s.srv.Export = fx
	k := newOwnKey(t)
	c := s.challenge(t, "vouchryx-token", "", vouchryxSecret)
	s.do(t, "POST", "/v1/keys/vouchryx-token/delegate", delegateBody(t, k, "vouchryx-token", "vouchryx", c, 3600), "", vouchryxSecret)
	if w, _ := s.adm(t, "POST", "/v1/kids/"+k.kid+"/revoke", 0); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d", w.Code)
	}
	if len(fx.kids) != 1 || fx.kids[0] != k.kid {
		t.Fatalf("the revocation was copied %v", fx.kids)
	}
}

func TestARevocationWhoseCopyFailedAnswers503AndStands(t *testing.T) {
	s := newDelegationStand(t)
	fx := &fakeExporter{}
	s.srv.Export = fx
	k := newOwnKey(t)
	c := s.challenge(t, "vouchryx-token", "", vouchryxSecret)
	s.do(t, "POST", "/v1/keys/vouchryx-token/delegate", delegateBody(t, k, "vouchryx-token", "vouchryx", c, 3600), "", vouchryxSecret)
	fx.fail = true
	if w, _ := s.adm(t, "POST", "/v1/kids/"+k.kid+"/revoke", 0); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("revoke with a copy that failed: %d", w.Code)
	}
	if _, revoked, _ := s.srv.Certs.Statement(k.kid); revoked == 0 {
		t.Fatal("the revocation did not stand")
	}
	if len(s.ann.got) != 1 || len(s.logLines(t)) == 0 {
		t.Fatalf("a copy that failed cost the other steps: announced %v", s.ann.got)
	}
}

func TestAChangeOfTheRootRewritesItsKeySetForTheReader(t *testing.T) {
	s := newDelegationStand(t)
	fx := &fakeExporter{}
	s.srv.Export = fx
	if w, _ := s.adm(t, "POST", "/v1/keys/"+statement.RootName+"/rotate", 0); w.Code != http.StatusOK || fx.roots != 1 {
		t.Fatalf("a root rotation: %d, root set written %d times", w.Code, fx.roots)
	}
	half := s.active(t, statement.RootES384)
	if w, _ := s.adm(t, "POST", "/v1/kids/"+half+"/revoke", 0); w.Code != http.StatusOK || fx.roots != 2 {
		t.Fatalf("a root half revoked: %d, root set written %d times", w.Code, fx.roots)
	}
	// A held key that is not the root is no statement and writes nothing.
	var other string
	for _, r := range s.srv.Store.Inventory() {
		if r.Name != statement.RootES384 && r.Name != statement.RootMLDSA && r.State == keystore.Active {
			other = r.Kid
		}
	}
	if other != "" {
		if w, _ := s.adm(t, "POST", "/v1/kids/"+other+"/revoke", 0); w.Code != http.StatusOK || fx.roots != 2 || len(fx.kids) != 0 {
			t.Fatalf("a held key revoked: %d, %d, %v", w.Code, fx.roots, fx.kids)
		}
	}
	fx.fail = true
	s.now = s.now.Add(20 * 60e9)
	if w, _ := s.adm(t, "POST", "/v1/keys/"+statement.RootName+"/rotate", 0); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("a root rotation whose copy failed: %d", w.Code)
	}
}

func TestTheRootSetIsWhatTheKeySetRouteServes(t *testing.T) {
	s := newDelegationStand(t)
	raw, err := s.srv.RootSet()
	if err != nil {
		t.Fatal(err)
	}
	w, _ := s.do(t, "GET", "/v1/jwks/"+statement.RootName, "", "", "")
	if got := w.Body.String(); got != string(raw)+"\n" {
		t.Fatalf("the copy %s is not what the route serves %s", raw, got)
	}
}
