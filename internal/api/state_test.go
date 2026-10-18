package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/certify"
	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/statement"
)

// editState rewrites one member of the record file whose name ends in file.
func editState(t *testing.T, dir, file string, edit func(map[string]any)) {
	t.Helper()
	var path string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(p, file) {
			path = p
		}
		return nil
	})
	if path == "" {
		t.Fatalf("no file %s under %s", file, dir)
	}
	raw, _ := os.ReadFile(path)
	var r map[string]any
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	edit(r)
	b, _ := json.Marshal(r)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTheStateRouteNamesEveryAlarm(t *testing.T) {
	s := newDelegationStand(t)
	dir := filepath.Dir(s.logPath)
	alarms := func() []map[string]any {
		w, body := s.do(t, "GET", "/v1/state", "", "", "")
		if w.Code != http.StatusOK {
			t.Fatalf("state: %d", w.Code)
		}
		var out []map[string]any
		raw, _ := json.Marshal(body["alarms"])
		_ = json.Unmarshal(raw, &out)
		return out
	}
	if a := alarms(); len(a) != 0 {
		t.Fatalf("control: alarms on an honest store: %v", a)
	}
	// A revoked held key and a revoked delegated key, each edited back.
	held, _ := s.srv.Store.Active("wardryx-approval")
	if _, err := s.srv.Store.Rotate("wardryx-approval", time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := s.srv.Store.Revoke(held.Kid); err != nil {
		t.Fatal(err)
	}
	k := newOwnKey(t)
	c := s.challenge(t, "vouchryx-token", "", vouchryxSecret)
	if w, _ := s.do(t, "POST", "/v1/keys/vouchryx-token/delegate", delegateBody(t, k, "vouchryx-token", "vouchryx", c, 3600), "", vouchryxSecret); w.Code != http.StatusOK {
		t.Fatalf("delegate: %d", w.Code)
	}
	if _, err := s.srv.Certs.Revoke(k.kid); err != nil {
		t.Fatal(err)
	}
	editState(t, filepath.Join(dir, "keys"), strings.ReplaceAll(held.Kid, ":", "_")+".json", func(r map[string]any) { r["state"], r["revoked"] = "retired", 0 })
	editState(t, filepath.Join(dir, "statements"), k.kid+".json", func(r map[string]any) { r["revoked"] = 0 })

	store, err := keystore.Open(dir, [32]byte{8, 8, 8}, append(s.srv.Policy.HeldKeys(), statement.RootKeys...), s.srv.Now)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	certs, err := certify.Open(dir, store, s.srv.Policy, 15*time.Minute, s.srv.Now)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	s.srv.Store, s.srv.Certs = store, certs
	s.h = s.srv.Handler()
	got := map[string]string{}
	for _, a := range alarms() {
		got[a["kid"].(string)] = a["kind"].(string)
		if a["reason"] == "" || a["name"] == "" {
			t.Errorf("an alarm without its name or reason: %v", a)
		}
	}
	if got[held.Kid] != "key" || got[k.kid] != "statement" || len(got) != 2 {
		t.Fatalf("the state route names %v, want the held key and the statement", got)
	}
	if s.jwksKids(t, "wardryx-approval")[held.Kid] || s.jwksKids(t, "vouchryx-token")[k.kid] {
		t.Fatal("a key whose state was edited back is published")
	}
}
