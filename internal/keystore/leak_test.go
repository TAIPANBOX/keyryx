package keystore_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crypto/sha256"

	"github.com/TAIPANBOX/keyryx/internal/api"
	"github.com/TAIPANBOX/keyryx/internal/auth"
	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/policy"
	"github.com/TAIPANBOX/keyryx/internal/uselog"
)

// No route answers with a private member (CLAUDE.md invariant 5), checked over
// the route table itself: every route api.Routes declares is called, with
// every credential that could open it, and nothing any of them answers
// carries a private key in any encoding. A route added to the table and not
// to this test fails the test, so the check cannot quietly miss one.
func TestNoRouteAnswersWithAPrivateMember(t *testing.T) {
	sum := sha256.Sum256([]byte("admin-key-0123456789abcdef"))
	adminDigest := "sha256:" + hex.EncodeToString(sum[:])
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
	admin, _ := auth.ParseAdminKeys(adminDigest)
	srv := &api.Server{Policy: p, Store: store, Log: ul, Auth: &auth.Verifier{Policy: p, Now: func() time.Time { return now }},
		AdminKeys: admin, PublishAhead: time.Minute, Now: func() time.Time { return now }}
	h := srv.Handler()

	call := func(method, path, body string, socket bool) []byte {
		req := httptest.NewRequest(method, "http://keyryx.test"+path, strings.NewReader(body))
		if socket {
			req = req.WithContext(api.WithSocketConsumer(context.Background(), "w"))
		}
		req.Header.Set("Authorization", "Bearer admin-key-0123456789abcdef")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code >= 500 {
			t.Fatalf("%s %s: %d", method, path, w.Code)
		}
		return w.Body.Bytes()
	}
	stmt := `{"statement_b64":"` + base64.StdEncoding.EncodeToString([]byte("x")) + `","purpose":"leak-test"}`
	exercised := map[string]bool{}
	var answers [][]byte
	for _, r := range api.Routes() {
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
			answers = append(answers, call(r.Method, path, body, r.Access == "consumer"))
			exercised[key] = true
		}
	}
	if len(exercised) == 0 {
		t.Fatal("api.Routes declares nothing, so this test measured nothing")
	}
	for _, r := range api.Routes() {
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
