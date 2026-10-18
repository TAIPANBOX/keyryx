package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/auth"
	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/policy"
	"github.com/TAIPANBOX/keyryx/internal/uselog"
)

// The custody surface: who may sign with which key, and what every refusal
// says to whom.

const (
	sealSecret  = "record-seal-consumer-key-0123456789"
	adminSecret = "admin-key-0123456789abcdef"
)

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

type stand struct {
	srv     *Server
	h       http.Handler
	logPath string
	now     time.Time
}

func newStand(t *testing.T) *stand {
	t.Helper()
	p, err := policy.Parse([]byte(`{"version":1,
 "keys":[{"name":"wardryx-approval","alg":"ES256"},{"name":"trailryx-root","alg":"ES384"}],
 "consumers":[
  {"name":"wardryx","auth":{"socket":"wardryx"},"grants":{"wardryx-approval":["sign"]}},
  {"name":"record-seal","auth":{"key_digest":"` + digest(sealSecret) + `"},"grants":{"trailryx-root":["sign"]}}
 ]}`))
	if err != nil {
		t.Fatalf("the test policy did not parse: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s := &stand{now: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	clock := func() time.Time { return s.now }
	store, err := keystore.Open(dir, [32]byte{7, 7, 7}, p.Keys, clock)
	if err != nil {
		t.Fatalf("the test store did not open: %v", err)
	}
	s.logPath = filepath.Join(dir, "use.ndjson")
	ul, err := uselog.Open(s.logPath)
	if err != nil {
		t.Fatalf("the test log did not open: %v", err)
	}
	t.Cleanup(func() { _ = ul.Close() })
	admin, err := auth.ParseAdminKeys(digest(adminSecret))
	if err != nil {
		t.Fatal(err)
	}
	s.srv = &Server{
		Policy: p, Store: store, Log: ul,
		Auth:         &auth.Verifier{Policy: p, Now: clock},
		AdminKeys:    admin,
		PublishAhead: 15 * time.Minute,
		Now:          clock,
	}
	s.h = s.srv.Handler()
	return s
}

// do sends one request. consumer, when set, marks the request as arriving on
// that consumer's socket; bearer, when set, is the Authorization header.
func (s *stand) do(t *testing.T, method, path, body, consumer, bearer string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, "http://keyryx.test"+path, strings.NewReader(body))
	if consumer != "" {
		req = req.WithContext(WithSocketConsumer(context.Background(), consumer))
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	s.h.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func signBody(statement, purpose string) string {
	b, _ := json.Marshal(map[string]string{"statement_b64": base64.StdEncoding.EncodeToString([]byte(statement)), "purpose": purpose})
	return string(b)
}

func (s *stand) logLines(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(s.logPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}

func TestAGrantedConsumerGetsASignatureAndTheUseIsLogged(t *testing.T) {
	s := newStand(t)
	w, body := s.do(t, "POST", "/v1/keys/wardryx-approval/sign", signBody("approve call 42", "approval"), "wardryx", "")
	if w.Code != http.StatusOK {
		t.Fatalf("a granted consumer got %d: %s", w.Code, w.Body)
	}
	sig, _ := base64.StdEncoding.DecodeString(body["signature_b64"].(string))
	pub, _ := base64.StdEncoding.DecodeString(body["public_key_b64"].(string))
	if body["alg"] != "ES256" || body["kid"] == "" {
		t.Fatalf("answer %v", body)
	}
	if err := keystore.Verify(policy.ES256, pub, []byte("approve call 42"), sig); err != nil {
		t.Fatalf("the signature does not verify: %v", err)
	}
	lines := s.logLines(t)
	sum := sha256.Sum256([]byte("approve call 42"))
	if len(lines) != 1 || !strings.Contains(lines[0], `"consumer":"wardryx"`) || !strings.Contains(lines[0], hex.EncodeToString(sum[:])) ||
		!strings.Contains(lines[0], `"key":"wardryx-approval"`) || !strings.Contains(lines[0], `"purpose":"approval"`) {
		t.Fatalf("the use is not on the record as it happened: %v", lines)
	}
	if strings.Contains(lines[0], "approve call 42") {
		t.Fatal("the log carries the statement itself; it must carry only its digest")
	}
	// The other way in: a bearer key over TCP.
	w, body = s.do(t, "POST", "/v1/keys/trailryx-root/sign", signBody("root 7", "seal"), "", sealSecret)
	if w.Code != http.StatusOK || body["alg"] != "ES384" {
		t.Fatalf("the key-authenticated consumer: %d %v", w.Code, body)
	}
}

func TestAConsumerCannotSignWithAKeyItWasNotGranted(t *testing.T) {
	s := newStand(t)
	if w, _ := s.do(t, "POST", "/v1/keys/wardryx-approval/sign", signBody("x", "approval"), "wardryx", ""); w.Code != http.StatusOK {
		t.Fatalf("control: %d", w.Code)
	}
	before := len(s.logLines(t))
	for name, c := range map[string][2]string{
		"another consumer's key by socket": {"/v1/keys/trailryx-root/sign", "wardryx"},
		"a key nobody declared":            {"/v1/keys/nope/sign", "wardryx"},
	} {
		w, body := s.do(t, "POST", c[0], signBody("x", "approval"), c[1], "")
		if w.Code != http.StatusForbidden || body["signature_b64"] != nil {
			t.Errorf("%s: %d %v", name, w.Code, body)
		}
	}
	if w, body := s.do(t, "POST", "/v1/keys/wardryx-approval/sign", signBody("x", "approval"), "", sealSecret); w.Code != http.StatusForbidden || body["signature_b64"] != nil {
		t.Errorf("another consumer's key by bearer: %d %v", w.Code, body)
	}
	if w, body := s.do(t, "POST", "/v1/keys/wardryx-approval/sign", signBody("x", "approval"), "intruder", ""); w.Code != http.StatusUnauthorized || body["signature_b64"] != nil {
		t.Errorf("a socket identity no consumer declares: %d %v", w.Code, body)
	}
	if after := len(s.logLines(t)); after != before {
		t.Fatalf("a refused request reached the use log as a use: %d -> %d", before, after)
	}
}

func TestAnUnauthenticatedCallerGetsNoSignature(t *testing.T) {
	s := newStand(t)
	for name, bearer := range map[string]string{"no credential": "", "a wrong key": "not-a-consumer-key", "the admin key": adminSecret} {
		w, body := s.do(t, "POST", "/v1/keys/trailryx-root/sign", signBody("x", "seal"), "", bearer)
		if w.Code != http.StatusUnauthorized || body["signature_b64"] != nil {
			t.Errorf("%s: %d %v", name, w.Code, body)
		}
	}
	if w, _ := s.do(t, "POST", "/v1/keys/trailryx-root/sign", signBody("x", "seal"), "", sealSecret); w.Code != http.StatusOK {
		t.Fatalf("control: %d", w.Code)
	}
}

func TestASignatureIsNotAnsweredWhenItsUseCouldNotBeLogged(t *testing.T) {
	s := newStand(t)
	if w, _ := s.do(t, "POST", "/v1/keys/wardryx-approval/sign", signBody("x", "approval"), "wardryx", ""); w.Code != http.StatusOK {
		t.Fatalf("control: %d", w.Code)
	}
	_ = s.srv.Log.Close()
	w, body := s.do(t, "POST", "/v1/keys/wardryx-approval/sign", signBody("y", "approval"), "wardryx", "")
	if w.Code != http.StatusServiceUnavailable || body["signature_b64"] != nil {
		t.Fatalf("a signature with no record of it: %d %v", w.Code, body)
	}
}

func TestHostileSignRequestsAreRefusedAndNeverPanic(t *testing.T) {
	s := newStand(t)
	if w, _ := s.do(t, "POST", "/v1/keys/wardryx-approval/sign", signBody("x", "approval"), "wardryx", ""); w.Code != http.StatusOK {
		t.Fatalf("control: %d", w.Code)
	}
	cases := map[string]string{
		"empty":                   "",
		"not JSON":                "{",
		"an array":                "[]",
		"an unknown field":        `{"statement_b64":"eA==","purpose":"p","alg":"none"}`,
		"two objects":             signBody("x", "p") + signBody("x", "p"),
		"statement not base64":    `{"statement_b64":"***","purpose":"p"}`,
		"statement empty":         `{"statement_b64":"","purpose":"p"}`,
		"no statement":            `{"purpose":"p"}`,
		"a purpose with a space":  signBody("x", "a purpose"),
		"a purpose too long":      signBody("x", strings.Repeat("p", 65)),
		"no purpose":              `{"statement_b64":"eA=="}`,
		"a purpose with newlines": signBody("x", "a\nforged line"),
		"a statement over 4 KiB":  signBody(strings.Repeat("s", keystore.MaxStatement+1), "p"),
		"a body over the cap":     `{"statement_b64":"` + strings.Repeat("A", 64<<10) + `","purpose":"p"}`,
		"a statement as a number": `{"statement_b64":5,"purpose":"p"}`,
	}
	for name, body := range cases {
		w, out := s.do(t, "POST", "/v1/keys/wardryx-approval/sign", body, "wardryx", "")
		if w.Code < 400 || out["signature_b64"] != nil {
			t.Errorf("%s: %d %v", name, w.Code, out)
		}
	}
	r := rand.New(rand.NewPCG(20261018, 4))
	alphabet := []byte(`{}[]",:=+/ABCabc019_- ` + "\x00\xff\n")
	base := []byte(signBody("hostile", "approval"))
	for i := 0; i < 1500; i++ {
		b := append([]byte(nil), base...)
		for k := 0; k <= r.IntN(5); k++ {
			b[r.IntN(len(b))] = alphabet[r.IntN(len(alphabet))]
		}
		w, out := s.do(t, "POST", "/v1/keys/wardryx-approval/sign", string(b), "wardryx", "")
		if w.Code == http.StatusOK {
			// A mutation that is still a valid request must sign what it says.
			var req struct {
				Statement string `json:"statement_b64"`
			}
			if json.Unmarshal(b, &req) != nil {
				t.Fatalf("case %d: an unparseable body was signed: %q", i, b)
			}
			stmt, _ := base64.StdEncoding.DecodeString(req.Statement)
			sig, _ := base64.StdEncoding.DecodeString(out["signature_b64"].(string))
			pub, _ := base64.StdEncoding.DecodeString(out["public_key_b64"].(string))
			if keystore.Verify(policy.ES256, pub, stmt, sig) != nil {
				t.Fatalf("case %d: signed something other than the statement sent", i)
			}
		}
	}
}

func TestTheKeySetPublishesActiveNextAndRetiredButNeverRevoked(t *testing.T) {
	s := newStand(t)
	jwks := func() []map[string]any {
		w, body := s.do(t, "GET", "/v1/jwks/trailryx-root", "", "", "")
		if w.Code != http.StatusOK {
			t.Fatalf("jwks: %d", w.Code)
		}
		cc := w.Header().Get("Cache-Control")
		_, age, found := strings.Cut(cc, "max-age=")
		secs, err := strconv.Atoi(age)
		if !found || err != nil {
			t.Errorf("the key set carries no cache lifetime: %q", cc)
		} else if time.Duration(secs)*time.Second > s.srv.PublishAhead/2 {
			// A verifier that caches longer than half the overlap can miss a
			// next key until after it has started signing.
			t.Errorf("the key set may be cached %ds, over half the %s publish-ahead time", secs, s.srv.PublishAhead)
		}
		var keys []map[string]any
		raw, _ := json.Marshal(body["keys"])
		_ = json.Unmarshal(raw, &keys)
		return keys
	}
	first := jwks()
	if len(first) != 1 {
		t.Fatalf("one active key, %d published", len(first))
	}
	oldKid := first[0]["kid"].(string)
	if w, _ := s.do(t, "POST", "/v1/keys/trailryx-root/rotate", "", "", adminSecret); w.Code != http.StatusOK {
		t.Fatalf("rotate: %d", w.Code)
	}
	if got := jwks(); len(got) != 2 {
		t.Fatalf("during the overlap %d keys are published, want 2", len(got))
	}
	s.now = s.now.Add(16 * time.Minute)
	if got := jwks(); len(got) != 2 {
		t.Fatalf("after the switch the retired key must stay published (evidence it signed must keep verifying): %d", len(got))
	}
	if w, _ := s.do(t, "POST", "/v1/kids/"+oldKid+"/revoke", "", "", adminSecret); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d", w.Code)
	}
	for _, k := range jwks() {
		if k["kid"] == oldKid {
			t.Fatal("a revoked key is still in the key set")
		}
	}
	if w, _ := s.do(t, "GET", "/v1/jwks/nope", "", "", ""); w.Code != http.StatusNotFound {
		t.Fatalf("an undeclared key set answered %d", w.Code)
	}
}

func TestAdminRoutesNeedAnAdminKey(t *testing.T) {
	s := newStand(t)
	for name, c := range map[string][2]string{
		"no credential":           {"", ""},
		"a wrong key":             {"", "not-the-admin"},
		"a consumer's key":        {"", sealSecret},
		"a consumer's own socket": {"wardryx", ""},
	} {
		if w, _ := s.do(t, "POST", "/v1/keys/wardryx-approval/rotate", "", c[0], c[1]); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: rotate answered %d", name, w.Code)
		}
	}
	s.srv.AdminKeys = nil
	if w, _ := s.do(t, "POST", "/v1/keys/wardryx-approval/rotate", "", "", adminSecret); w.Code != http.StatusForbidden {
		t.Errorf("with no admin keys configured, rotate answered %d", w.Code)
	}
	s.srv.AdminKeys, _ = auth.ParseAdminKeys(digest(adminSecret))
	if w, _ := s.do(t, "POST", "/v1/keys/wardryx-approval/rotate", "", "", adminSecret); w.Code != http.StatusOK {
		t.Fatalf("control: %d", w.Code)
	}
	if w, _ := s.do(t, "POST", "/v1/keys/wardryx-approval/rotate", "", "", adminSecret); w.Code != http.StatusConflict {
		t.Fatalf("a second rotation while one is pending answered %d", w.Code)
	}
	if w, _ := s.do(t, "POST", "/v1/kids/no-such-kid/revoke", "", "", adminSecret); w.Code != http.StatusNotFound {
		t.Fatalf("revoking an unknown kid answered %d", w.Code)
	}
	lines := s.logLines(t)
	if len(lines) == 0 || !strings.Contains(lines[len(lines)-1], `"op":"rotate"`) || !strings.Contains(lines[len(lines)-1], `"consumer":"admin:`) {
		t.Fatalf("a rotation is not on the use log under its admin key's fingerprint: %v", lines)
	}
	if strings.Contains(strings.Join(lines, "\n"), adminSecret) {
		t.Fatal("the admin key itself reached the log")
	}
}

// The route table is the mux, both ways: every route it names is served, and
// nothing it does not name is.
func TestTheRouteTableIsTheMux(t *testing.T) {
	s := newStand(t)
	routes := Routes()
	if len(routes) == 0 {
		t.Fatal("no route is declared, so this test measured nothing")
	}
	for _, r := range routes {
		path := strings.NewReplacer("{name}", "wardryx-approval", "{kid}", "no-such-kid").Replace(r.Pattern)
		w, _ := s.do(t, r.Method, path, "", "", "")
		if w.Code == http.StatusNotFound && !strings.Contains(r.Pattern, "{kid}") || w.Code == http.StatusMethodNotAllowed {
			t.Errorf("%s %s is declared and the mux does not serve it: %d", r.Method, r.Pattern, w.Code)
		}
		switch r.Access {
		case "public":
			if w.Code >= 400 {
				t.Errorf("%s %s is public and refused a caller with no credential: %d", r.Method, r.Pattern, w.Code)
			}
		case "consumer", "admin":
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s %s needs a credential and answered %d without one", r.Method, r.Pattern, w.Code)
			}
		default:
			t.Errorf("%s %s has access %q, which is none of public, consumer, admin", r.Method, r.Pattern, r.Access)
		}
	}
	for _, p := range []string{"/", "/v1", "/v1/keys/wardryx-approval", "/v1/keys/wardryx-approval/private", "/v1/introspect", "/debug/pprof/"} {
		if w, _ := s.do(t, "GET", p, "", "", ""); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s is served though no route names it: %d", p, w.Code)
		}
	}
}

func TestARefusalNamesItsReasonInTheLogAndNotInTheAnswer(t *testing.T) {
	s := newStand(t)
	var buf strings.Builder
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	for _, c := range []struct {
		reason       string
		path, socket string
		bearer       string
	}{
		{"key_not_granted", "/v1/keys/trailryx-root/sign", "wardryx", ""},
		{"consumer_unknown", "/v1/keys/trailryx-root/sign", "", "nobody"},
	} {
		buf.Reset()
		w, _ := s.do(t, "POST", c.path, signBody("x", "seal"), c.socket, c.bearer)
		if w.Code < 400 {
			t.Fatalf("%s: not refused", c.reason)
		}
		if !strings.Contains(buf.String(), c.reason) {
			t.Errorf("the log does not name %q: %q", c.reason, buf.String())
		}
		if strings.Contains(w.Body.String(), c.reason) {
			t.Errorf("the reason %q reached the caller: %s", c.reason, w.Body)
		}
	}
}
