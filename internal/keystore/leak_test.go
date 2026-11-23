package keystore_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/announce"
	"github.com/TAIPANBOX/keyryx/internal/api"
	"github.com/TAIPANBOX/keyryx/internal/auth"
	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/policy"
	"github.com/TAIPANBOX/keyryx/internal/uselog"
)

// No route answers with a private member (CLAUDE.md invariant 5), checked over
// the route tables themselves: every route api.Routes and api.AdminRoutes
// declare is called, and every announcement an admin change makes is read, with
// every credential that could open it, and nothing any of them answers
// carries a private key in any encoding. A route added to the table and not
// to this test fails the test, so the check cannot quietly miss one.
// keptAnnouncements keeps what an admin change would put on the bus, so the
// leak check reads that too.
type keptAnnouncements struct{ got []announce.Announcement }

func (k *keptAnnouncements) Enqueue(a announce.Announcement) error {
	k.got = append(k.got, a)
	return nil
}

func (k *keptAnnouncements) Has(typ, kid string) bool {
	for _, a := range k.got {
		if a.Type == typ && a.Data["kid"] == kid {
			return true
		}
	}
	return false
}

func (k *keptAnnouncements) Count(typ, name string) int {
	n := 0
	for _, a := range k.got {
		if a.Type == typ && a.Data["name"] == name {
			n++
		}
	}
	return n
}

func (k *keptAnnouncements) Pending() int { return len(k.got) }

func TestNoRouteAnswersWithAPrivateMember(t *testing.T) {
	p, err := policy.Parse([]byte(`{"version":1,
 "keys":[{"name":"a","alg":"ES256"},{"name":"b","alg":"ES384"},{"name":"c","alg":"ML-DSA-65"}],
 "consumers":[{"name":"w","auth":{"socket":"w"},"grants":{"a":["sign"],"b":["sign"],"c":["sign"]}}]}`))
	if err != nil {
		t.Fatalf("the test policy did not parse: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	store, err := keystore.Open(dir, [32]byte{9}, p.Keys, func() time.Time { return now })
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ul, err := uselog.Open(filepath.Join(dir, "use.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	defer ul.Close()
	ann := &keptAnnouncements{}
	srv := &api.Server{Policy: p, Store: store, Log: ul, Auth: &auth.Verifier{Policy: p, Now: func() time.Time { return now }},
		Announce: ann, PublishAhead: time.Minute, Now: func() time.Time { return now }}
	h, adminH := srv.Handler(), srv.AdminHandler()

	call := func(method, path, body, access string) []byte {
		req := httptest.NewRequest(method, "http://keyryx.test"+path, strings.NewReader(body))
		mux := h
		switch access {
		case "consumer":
			req = req.WithContext(api.WithSocketConsumer(context.Background(), "w"))
		case "admin":
			req = req.WithContext(api.WithAdminPeer(context.Background(), 0))
			mux = adminH
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code >= 500 {
			t.Fatalf("%s %s: %d", method, path, w.Code)
		}
		return w.Body.Bytes()
	}
	stmt := `{"statement_b64":"` + base64.StdEncoding.EncodeToString([]byte("x")) + `","purpose":"leak-test"}`
	exercised := map[string]bool{}
	var answers [][]byte
	all := append(api.Routes(), api.AdminRoutes()...)
	for _, r := range all {
		key := r.Method + " " + r.Pattern
		for _, name := range []string{"a", "b", "c"} {
			path := strings.ReplaceAll(r.Pattern, "{name}", name)
			if strings.Contains(path, "{kid}") {
				recs, _ := store.Published(name)
				path = strings.ReplaceAll(path, "{kid}", recs[len(recs)-1].Kid)
			}
			body := ""
			if strings.HasSuffix(r.Pattern, "/sign") {
				body = stmt
			}
			answers = append(answers, call(r.Method, path, body, r.Access))
			exercised[key] = true
		}
	}
	if len(exercised) == 0 {
		t.Fatal("api.Routes declares nothing, so this test measured nothing")
	}
	if len(ann.got) == 0 {
		t.Fatal("no admin change was announced, so the announcements measured nothing")
	}
	for _, a := range ann.got {
		b, _ := json.Marshal(a)
		answers = append(answers, b)
	}
	for _, r := range all {
		if !exercised[r.Method+" "+r.Pattern] {
			t.Errorf("%s %s was not exercised", r.Method, r.Pattern)
		}
	}
	secrets := keystore.PrivateMaterial(store)
	if len(secrets) < 3 {
		t.Fatalf("the store reports %d private encodings for 3 keys, so this test measured nothing", len(secrets))
	}
	for _, a := range answers {
		for _, sec := range secrets {
			for _, form := range [][]byte{sec, []byte(base64.StdEncoding.EncodeToString(sec)), []byte(base64.RawURLEncoding.EncodeToString(sec)), []byte(hex.EncodeToString(sec))} {
				if bytes.Contains(a, form) {
					t.Fatalf("a route answered with a private key: %s", a)
				}
			}
		}
		for _, member := range []string{`"d":`, `"priv`, `"seed"`, `"wrapped"`, `"private`} {
			if bytes.Contains(a, []byte(member)) {
				t.Fatalf("a route answered with a member named like a private one (%s): %s", member, a)
			}
		}
	}
	_ = http.StatusOK
}
