package api

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/announce"
	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/statement"
)

// What the bus hears of an admin's change to a key (invariant 43).

func (s *stand) active(t *testing.T, name string) string {
	t.Helper()
	recs, _ := s.srv.Store.Published(name)
	for _, r := range recs {
		if r.State == keystore.Active {
			return r.Kid
		}
	}
	t.Fatalf("%s has no active key", name)
	return ""
}

func TestEveryAdminChangeIsAnnounced(t *testing.T) {
	s := newStand(t)
	first := s.active(t, "wardryx-approval")
	w, body := s.adm(t, "POST", "/v1/keys/wardryx-approval/rotate", 0)
	if w.Code != http.StatusOK {
		t.Fatalf("rotate: %d", w.Code)
	}
	next := body["kid"].(string)
	want := []announce.Announcement{announce.Rotated("wardryx-approval", next, first, "ES256")}
	if !reflect.DeepEqual(s.ann.got, want) {
		t.Fatalf("a rotation announced %v, want %v", s.ann.got, want)
	}

	// Revoking a key that is not active: one key_revoked.
	s.ann.got = nil
	if w, _ := s.adm(t, "POST", "/v1/kids/"+next+"/revoke", 0); w.Code != http.StatusOK {
		t.Fatalf("revoke the next key: %d", w.Code)
	}
	if want := []announce.Announcement{announce.Revoked("wardryx-approval", next, "ES256")}; !reflect.DeepEqual(s.ann.got, want) {
		t.Fatalf("revoking a next key announced %v, want %v", s.ann.got, want)
	}

	// The same kid again: it was revoked already, and is not announced twice.
	s.ann.got = nil
	if w, _ := s.adm(t, "POST", "/v1/kids/"+next+"/revoke", 0); w.Code != http.StatusOK {
		t.Fatalf("revoke again: %d", w.Code)
	}
	if len(s.ann.got) != 0 {
		t.Fatalf("a revocation of a revoked kid was announced again: %v", s.ann.got)
	}

	// Revoking the active key: custody makes a fresh one at once, and that is
	// a rotation the bus hears of too, from the revoked kid.
	s.ann.got = nil
	if w, _ := s.adm(t, "POST", "/v1/kids/"+first+"/revoke", custodyUID); w.Code != http.StatusOK {
		t.Fatalf("revoke the active key: %d", w.Code)
	}
	fresh := s.active(t, "wardryx-approval")
	if fresh == first {
		t.Fatal("control: the revoked key is still active")
	}
	want = []announce.Announcement{announce.Revoked("wardryx-approval", first, "ES256"), announce.Rotated("wardryx-approval", fresh, first, "ES256")}
	if !reflect.DeepEqual(s.ann.got, want) {
		t.Fatalf("revoking the active key announced %v, want %v", s.ann.got, want)
	}

	// Revoking the active key with a next one pending promotes the next one,
	// whose rotation the bus has already heard of: one key_revoked.
	s.ann.got = nil
	_, body = s.adm(t, "POST", "/v1/keys/trailryx-root/rotate", 0)
	pending := body["kid"].(string)
	old := s.active(t, "trailryx-root")
	s.ann.got = nil
	if w, _ := s.adm(t, "POST", "/v1/kids/"+old+"/revoke", 0); w.Code != http.StatusOK {
		t.Fatalf("revoke with a next key: %d", w.Code)
	}
	want = []announce.Announcement{announce.Revoked("trailryx-root", old, "ES384")}
	if s.active(t, "trailryx-root") != pending {
		t.Fatal("control: the next key was not promoted")
	}
	if !reflect.DeepEqual(s.ann.got, want) {
		t.Fatalf("revoking the active key with a next one announced %v, want %v", s.ann.got, want)
	}
}

func TestAnAdminChangeWhoseAnnouncementDidNotQueueIsHealedByAskingAgain(t *testing.T) {
	s := newStand(t)
	first := s.active(t, "wardryx-approval")
	s.ann.fail = true
	if w, _ := s.adm(t, "POST", "/v1/keys/wardryx-approval/rotate", 0); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("rotate with an outbox that refuses: %d", w.Code)
	}
	next, ok := s.srv.nextRecord("wardryx-approval")
	if !ok {
		t.Fatal("the rotation did not stand")
	}
	if lines := s.logLines(t); len(lines) != 1 || !strings.Contains(lines[0], next.Kid) {
		t.Fatalf("an announcement that did not queue cost the use-log line: %v", lines)
	}
	// Asking again is a second rotation, refused, and it announces the first.
	s.ann.fail = false
	if w, _ := s.adm(t, "POST", "/v1/keys/wardryx-approval/rotate", 0); w.Code != http.StatusConflict {
		t.Fatalf("rotate again: %d", w.Code)
	}
	if want := []announce.Announcement{announce.Rotated("wardryx-approval", next.Kid, first, "ES256")}; !reflect.DeepEqual(s.ann.got, want) {
		t.Fatalf("asking again announced %v, want %v", s.ann.got, want)
	}
	s.ann.got = nil
	if w, _ := s.adm(t, "POST", "/v1/keys/wardryx-approval/rotate", 0); w.Code != http.StatusConflict || len(s.ann.got) != 0 {
		t.Fatalf("a third ask: %d, announced %v", w.Code, s.ann.got)
	}

	// A revocation whose announcement did not queue: asking again announces it, once.
	s.ann.fail = true
	if w, _ := s.adm(t, "POST", "/v1/kids/"+next.Kid+"/revoke", 0); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("revoke with an outbox that refuses: %d", w.Code)
	}
	if recs, _ := s.srv.Store.Published("wardryx-approval"); len(recs) != 1 {
		t.Fatalf("the revocation did not stand: %d keys published", len(recs))
	}
	s.ann.fail = false
	for i := 0; i < 2; i++ {
		if w, _ := s.adm(t, "POST", "/v1/kids/"+next.Kid+"/revoke", 0); w.Code != http.StatusOK {
			t.Fatalf("revoke again: %d", w.Code)
		}
	}
	if want := []announce.Announcement{announce.Revoked("wardryx-approval", next.Kid, "ES256")}; !reflect.DeepEqual(s.ann.got, want) {
		t.Fatalf("asking again announced %v, want %v", s.ann.got, want)
	}
}

func TestNoAdminChangeWithoutAnAnnouncer(t *testing.T) {
	s := newStand(t)
	s.srv.Announce = nil
	before := s.active(t, "wardryx-approval")
	if w, _ := s.adm(t, "POST", "/v1/keys/wardryx-approval/rotate", 0); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("rotate with no announcer: %d", w.Code)
	}
	if w, _ := s.adm(t, "POST", "/v1/kids/"+before+"/revoke", 0); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("revoke with no announcer: %d", w.Code)
	}
	recs, _ := s.srv.Store.Published("wardryx-approval")
	if len(recs) != 1 || s.active(t, "wardryx-approval") != before || len(s.logLines(t)) != 0 {
		t.Fatal("a change was made that nobody could be told of")
	}
}

func TestTheStateRouteSaysHowManyChangesWaitForTheBus(t *testing.T) {
	s := newStand(t)
	if _, body := s.do(t, "GET", "/v1/state", "", "", ""); body["unannounced"] != float64(0) {
		t.Fatalf("unannounced before any change: %v", body["unannounced"])
	}
	s.adm(t, "POST", "/v1/keys/wardryx-approval/rotate", 0)
	if _, body := s.do(t, "GET", "/v1/state", "", "", ""); body["unannounced"] != float64(1) {
		t.Fatalf("unannounced after one change: %v", body["unannounced"])
	}
}

func TestAHalfFinishedRootRotationIsCompleted(t *testing.T) {
	for _, late := range []bool{false, true} {
		s := newDelegationStand(t)
		es, ml := s.active(t, statement.RootES384), s.active(t, statement.RootMLDSA)
		// A rotation that stopped after its first half: the ES384 half rotated
		// and was announced, and the store failed before the ML-DSA one.
		rec, err := s.srv.Store.Rotate(statement.RootES384, s.srv.PublishAhead)
		if err != nil {
			t.Fatal(err)
		}
		_ = s.ann.Enqueue(announce.Rotated(statement.RootES384, rec.Kid, es, "ES384"))
		s.ann.got = nil
		if late {
			// Asked again only after the first half's next key is active.
			s.now = s.now.Add(16 * time.Minute)
			if s.active(t, statement.RootES384) != rec.Kid {
				t.Fatal("control: the ES384 half's next key did not activate")
			}
		}
		w, body := s.adm(t, "POST", "/v1/keys/"+statement.RootName+"/rotate", 0)
		if w.Code != http.StatusOK {
			t.Fatalf("late=%v: completing the rotation: %d", late, w.Code)
		}
		keys := body["keys"].([]any)
		if len(keys) != 1 || keys[0].(map[string]any)["name"] != statement.RootMLDSA {
			t.Fatalf("late=%v: the completion rotated %v, want the ML-DSA half alone", late, keys)
		}
		kid := keys[0].(map[string]any)["kid"].(string)
		if want := []announce.Announcement{announce.Rotated(statement.RootMLDSA, kid, ml, "ML-DSA-65")}; !reflect.DeepEqual(s.ann.got, want) {
			t.Fatalf("late=%v: the completion announced %v, want %v", late, s.ann.got, want)
		}
		if recs, _ := s.srv.Store.Published(statement.RootES384); len(recs) != 2 {
			t.Fatalf("late=%v: the ES384 half was rotated again: %d keys", late, len(recs))
		}
		if !late {
			if w, _ := s.adm(t, "POST", "/v1/keys/"+statement.RootName+"/rotate", 0); w.Code != http.StatusConflict {
				t.Fatalf("a rotation with both halves pending: %d", w.Code)
			}
		}
	}

	// A half rotated and never announced (the process died in between):
	// asking announces it and refuses a second rotation.
	s := newDelegationStand(t)
	es := s.active(t, statement.RootES384)
	rec, _ := s.srv.Store.Rotate(statement.RootES384, s.srv.PublishAhead)
	if w, _ := s.adm(t, "POST", "/v1/keys/"+statement.RootName+"/rotate", 0); w.Code != http.StatusConflict {
		t.Fatalf("a root with an unannounced next half: %d", w.Code)
	}
	if want := []announce.Announcement{announce.Rotated(statement.RootES384, rec.Kid, es, "ES384")}; !reflect.DeepEqual(s.ann.got, want) {
		t.Fatalf("the unannounced half: %v, want %v", s.ann.got, want)
	}

	// A whole rotation announces both halves.
	s = newDelegationStand(t)
	es2, ml2 := s.active(t, statement.RootES384), s.active(t, statement.RootMLDSA)
	w, body := s.adm(t, "POST", "/v1/keys/"+statement.RootName+"/rotate", 0)
	if w.Code != http.StatusOK || len(body["keys"].([]any)) != 2 {
		t.Fatalf("a whole rotation: %d %v", w.Code, body)
	}
	if len(s.ann.got) != 2 || s.ann.got[0].Data["previous_kid"] != es2 || s.ann.got[1].Data["previous_kid"] != ml2 ||
		s.ann.got[0].Data["alg"] != "ES384" || s.ann.got[1].Data["alg"] != "ML-DSA-65" {
		t.Fatalf("a whole root rotation announced %v", s.ann.got)
	}
	// And the next whole rotation, once both are active, does too.
	s.now = s.now.Add(16 * time.Minute)
	s.ann.got = nil
	if w, body := s.adm(t, "POST", "/v1/keys/"+statement.RootName+"/rotate", 0); w.Code != http.StatusOK || len(body["keys"].([]any)) != 2 || len(s.ann.got) != 2 {
		t.Fatalf("a second whole rotation: %d %v %v", w.Code, body, s.ann.got)
	}
}

func TestARenewalOrARetirementIsNotAnnounced(t *testing.T) {
	s := newDelegationStand(t)
	for i := 0; i < 6; i++ {
		k := newOwnKey(t)
		c := s.challenge(t, "vouchryx-token", "", vouchryxSecret)
		if w, _ := s.do(t, "POST", "/v1/keys/vouchryx-token/delegate", delegateBody(t, k, "vouchryx-token", "vouchryx", c, 3600), "", vouchryxSecret); w.Code != http.StatusOK {
			t.Fatalf("delegate %d: %d %s", i, w.Code, w.Body)
		}
		s.now = s.now.Add(20 * time.Minute)
	}
	if len(s.ann.got) != 0 {
		t.Fatalf("a consumer's own renewal or retirement was announced: %v", s.ann.got)
	}
}

func TestAnAdminRevocationOfADelegatedKeyIsAnnounced(t *testing.T) {
	s := newDelegationStand(t)
	k := newOwnKey(t)
	c := s.challenge(t, "vouchryx-token", "", vouchryxSecret)
	if w, _ := s.do(t, "POST", "/v1/keys/vouchryx-token/delegate", delegateBody(t, k, "vouchryx-token", "vouchryx", c, 3600), "", vouchryxSecret); w.Code != http.StatusOK {
		t.Fatalf("control: %d", w.Code)
	}
	if w, _ := s.adm(t, "POST", "/v1/kids/"+k.kid+"/revoke", 0); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d", w.Code)
	}
	if want := []announce.Announcement{announce.Revoked("vouchryx-token", k.kid, "ES256")}; !reflect.DeepEqual(s.ann.got, want) {
		t.Fatalf("revoking a delegated key announced %v, want %v", s.ann.got, want)
	}
	s.ann.got = nil
	if w, _ := s.adm(t, "POST", "/v1/kids/"+k.kid+"/revoke", 0); w.Code != http.StatusOK {
		t.Fatalf("revoke again: %d", w.Code)
	}
	if len(s.ann.got) != 0 {
		t.Fatalf("a delegated kid revoked twice was announced twice: %v", s.ann.got)
	}
}

func TestAnAdminChangeWhoseUseLogDidNotWriteIsStillAnnounced(t *testing.T) {
	s := newStand(t)
	first := s.active(t, "wardryx-approval")
	_ = s.srv.Log.Close()
	w, _ := s.adm(t, "POST", "/v1/keys/wardryx-approval/rotate", 0)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("rotate with a use log that does not write: %d", w.Code)
	}
	next, ok := s.srv.nextRecord("wardryx-approval")
	if !ok {
		t.Fatal("the rotation did not stand")
	}
	if want := []announce.Announcement{announce.Rotated("wardryx-approval", next.Kid, first, "ES256")}; !reflect.DeepEqual(s.ann.got, want) {
		t.Fatalf("a use log that did not write cost the announcement: %v", s.ann.got)
	}
}
