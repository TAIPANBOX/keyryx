package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
	"github.com/TAIPANBOX/keyryx/internal/auth"
	"github.com/TAIPANBOX/keyryx/internal/certify"
	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/policy"
	"github.com/TAIPANBOX/keyryx/internal/statement"
	"github.com/TAIPANBOX/keyryx/internal/uselog"
)

// The delegation surface: who may have which key certified, and what a
// verifier then trusts.

const vouchryxSecret = "vouchryx-consumer-key-0123456789"

func newDelegationStand(t *testing.T) *stand {
	t.Helper()
	p, err := policy.Parse([]byte(`{"version":1,
 "keys":[{"name":"wardryx-approval","alg":"ES256"},
  {"name":"vouchryx-token","alg":"ES256","mode":"delegated","max_lifetime":"72h","overlap":"10m"},
  {"name":"wardryx-stream","alg":"ES256","mode":"delegated","max_lifetime":"24h"}],
 "consumers":[
  {"name":"wardryx","auth":{"socket":"wardryx"},"grants":{"wardryx-approval":["sign"],"wardryx-stream":["delegate"]}},
  {"name":"vouchryx","auth":{"key_digest":"` + digest(vouchryxSecret) + `"},"grants":{"vouchryx-token":["delegate"]}}
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
	store, err := keystore.Open(dir, [32]byte{8, 8, 8}, append(p.HeldKeys(), statement.RootKeys...), clock)
	if err != nil {
		t.Fatalf("the test store did not open: %v", err)
	}
	certs, err := certify.Open(dir, store, p, 15*time.Minute, clock)
	if err != nil {
		t.Fatalf("the test registry did not open: %v", err)
	}
	s.logPath = filepath.Join(dir, "use.ndjson")
	ul, err := uselog.Open(s.logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ul.Close() })
	admin, _ := auth.ParseAdminKeys(digest(adminSecret))
	s.srv = &Server{Policy: p, Store: store, Certs: certs, Log: ul, Auth: &auth.Verifier{Policy: p, Now: clock},
		AdminKeys: admin, PublishAhead: 15 * time.Minute, Now: clock}
	s.h = s.srv.Handler()
	return s
}

type ownKey struct {
	key *ecdsa.PrivateKey
	jwk map[string]any
	kid string
}

func newOwnKey(t *testing.T) ownKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j := delegation.FromPublic(&k.PublicKey, "")
	kid, _ := delegation.Thumbprint(j)
	return ownKey{key: k, jwk: map[string]any{"kty": j.Kty, "crv": j.Crv, "x": j.X, "y": j.Y}, kid: kid}
}

func (k ownKey) proof(t *testing.T, name, consumer, challenge string) string {
	t.Helper()
	d := sha256.Sum256(statement.ProofInput(name, consumer, k.kid, challenge))
	r, s, err := ecdsa.Sign(rand.Reader, k.key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

// challenge asks for a challenge as consumer (socket) or bearer.
func (s *stand) challenge(t *testing.T, name, socket, bearer string) string {
	t.Helper()
	w, body := s.do(t, "POST", "/v1/keys/"+name+"/challenge", "", socket, bearer)
	if w.Code != http.StatusOK {
		t.Fatalf("challenge for %s: %d %s", name, w.Code, w.Body)
	}
	c, _ := body["challenge"].(string)
	if c == "" {
		t.Fatalf("challenge answer %v", body)
	}
	return c
}

func delegateBody(t *testing.T, k ownKey, name, consumer, challenge string, life int) string {
	b, _ := json.Marshal(map[string]any{"jwk": k.jwk, "challenge": challenge, "proof_b64": k.proof(t, name, consumer, challenge), "lifetime_s": life})
	return string(b)
}

func (s *stand) jwksKids(t *testing.T, name string) map[string]bool {
	t.Helper()
	w, body := s.do(t, "GET", "/v1/jwks/"+name, "", "", "")
	out := map[string]bool{}
	if w.Code != http.StatusOK {
		return out
	}
	keys, _ := body["keys"].([]any)
	for _, k := range keys {
		m, _ := k.(map[string]any)
		kid, _ := m["kid"].(string)
		out[kid] = true
	}
	return out
}

func TestAGrantedConsumerGetsAStatementThroughTheRoutes(t *testing.T) {
	s := newDelegationStand(t)
	k := newOwnKey(t)
	c := s.challenge(t, "vouchryx-token", "", vouchryxSecret)
	w, body := s.do(t, "POST", "/v1/keys/vouchryx-token/delegate", delegateBody(t, k, "vouchryx-token", "vouchryx", c, 86400), "", vouchryxSecret)
	if w.Code != http.StatusOK {
		t.Fatalf("delegate: %d %s", w.Code, w.Body)
	}
	if body["kid"] != k.kid || body["not_before"] != float64(s.now.Unix()) || body["not_after"] != float64(s.now.Add(24*time.Hour).Unix()) {
		t.Fatalf("answer %v", body)
	}
	raw, _ := json.Marshal(body["statement"])
	st, err := statement.Verify(raw, statement.StoreRoots(s.srv.Store))
	if err != nil {
		t.Fatalf("the statement answered does not verify under both halves of the root: %v", err)
	}
	if st.Kid != k.kid || st.Owner != "vouchryx" || st.Name != "vouchryx-token" {
		t.Fatalf("statement %+v", st)
	}
	lines := s.logLines(t)
	if len(lines) != 1 || !strings.Contains(lines[0], `"op":"delegate"`) || !strings.Contains(lines[0], `"consumer":"vouchryx"`) ||
		!strings.Contains(lines[0], `"kid":"`+k.kid+`"`) || !strings.Contains(lines[0], `"key":"vouchryx-token"`) {
		t.Fatalf("the certification is not on the use log: %v", lines)
	}
	// The statement is served by its key id.
	w, served := s.do(t, "GET", "/v1/statements/"+k.kid, "", "", "")
	sraw, _ := json.Marshal(served["statement"])
	if w.Code != http.StatusOK || string(sraw) != string(raw) || served["revoked_at"] != float64(0) {
		t.Fatalf("GET statement: %d %v", w.Code, served)
	}
	// The key set, read by the estate's shared verifier, accepts a token the
	// consumer signed with its own key.
	w, _ = s.do(t, "GET", "/v1/jwks/vouchryx-token", "", "", "")
	var set delegation.Set
	if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil || len(set.Keys) != 1 {
		t.Fatalf("the key set: %v %s", err, w.Body)
	}
	tok, err := delegation.SignES256(k.key, k.kid, map[string]any{"sub": "agent://acme.example/one"})
	if err != nil {
		t.Fatal(err)
	}
	if claims, err := delegation.VerifyToken(tok, set); err != nil || claims["sub"] != "agent://acme.example/one" {
		t.Fatalf("the shared verifier refused a token from the certified key: %v", err)
	}
	other := newOwnKey(t)
	if tok2, _ := delegation.SignES256(other.key, k.kid, map[string]any{"sub": "x"}); func() bool { _, err := delegation.VerifyToken(tok2, set); return err == nil }() {
		t.Fatal("a token from another key under the certified kid verified")
	}
	// The inventory names it, as delegated.
	_, inv := s.do(t, "GET", "/v1/keys", "", "", "")
	found := false
	for _, e := range inv["keys"].([]any) {
		m := e.(map[string]any)
		if m["kid"] == k.kid && m["mode"] == "delegated" && m["owner"] == "vouchryx" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the inventory does not name the certified key: %v", inv)
	}
	// Over a socket too.
	k2 := newOwnKey(t)
	c2 := s.challenge(t, "wardryx-stream", "wardryx", "")
	if w, _ := s.do(t, "POST", "/v1/keys/wardryx-stream/delegate", delegateBody(t, k2, "wardryx-stream", "wardryx", c2, 3600), "wardryx", ""); w.Code != http.StatusOK {
		t.Fatalf("delegate over the socket: %d %s", w.Code, w.Body)
	}
	if !s.jwksKids(t, "wardryx-stream")[k2.kid] {
		t.Fatal("the socket consumer's key is not published")
	}
}

func TestDelegationRefusesWhatWasNotGranted(t *testing.T) {
	s := newDelegationStand(t)
	k := newOwnKey(t)
	for name, c := range map[string]struct {
		method, path, body, socket, bearer string
		want                               int
	}{
		"a challenge for a key not granted":     {"POST", "/v1/keys/vouchryx-token/challenge", "", "wardryx", "", http.StatusForbidden},
		"a delegate for a key not granted":      {"POST", "/v1/keys/vouchryx-token/delegate", delegateBody(t, k, "vouchryx-token", "wardryx", "c", 3600), "wardryx", "", http.StatusForbidden},
		"a sign asked of a delegated key":       {"POST", "/v1/keys/vouchryx-token/sign", signBody("x", "token"), "", vouchryxSecret, http.StatusForbidden},
		"a challenge for a held key":            {"POST", "/v1/keys/wardryx-approval/challenge", "", "wardryx", "", http.StatusForbidden},
		"a sign asked of the delegation root":   {"POST", "/v1/keys/" + statement.RootES384 + "/sign", signBody("x", "root"), "wardryx", "", http.StatusForbidden},
		"the ML-DSA half of the root":           {"POST", "/v1/keys/" + statement.RootMLDSA + "/sign", signBody("x", "root"), "wardryx", "", http.StatusForbidden},
		"a challenge with no credential":        {"POST", "/v1/keys/vouchryx-token/challenge", "", "", "", http.StatusUnauthorized},
		"a delegate with no credential":         {"POST", "/v1/keys/vouchryx-token/delegate", "{}", "", "", http.StatusUnauthorized},
		"a delegate with a wrong key":           {"POST", "/v1/keys/vouchryx-token/delegate", "{}", "", "not-a-consumer", http.StatusUnauthorized},
		"a challenge for a key nobody declared": {"POST", "/v1/keys/nope/challenge", "", "", vouchryxSecret, http.StatusForbidden},
	} {
		w, body := s.do(t, c.method, c.path, c.body, c.socket, c.bearer)
		if w.Code != c.want || body["statement"] != nil || body["signature_b64"] != nil || body["challenge"] != nil {
			t.Errorf("%s: %d %v, want %d", name, w.Code, body, c.want)
		}
	}
	if lines := s.logLines(t); len(lines) != 0 {
		t.Fatalf("a refusal reached the use log: %v", lines)
	}
	if len(s.jwksKids(t, "vouchryx-token")) != 0 {
		t.Fatal("something was certified")
	}
	// Control: the grant that exists works.
	c := s.challenge(t, "vouchryx-token", "", vouchryxSecret)
	if w, _ := s.do(t, "POST", "/v1/keys/vouchryx-token/delegate", delegateBody(t, k, "vouchryx-token", "vouchryx", c, 3600), "", vouchryxSecret); w.Code != http.StatusOK {
		t.Fatalf("control: %d %s", w.Code, w.Body)
	}
}

func TestHostileDelegateRequestsAreRefusedAndNeverPanic(t *testing.T) {
	s := newDelegationStand(t)
	k := newOwnKey(t)
	const name, who = "vouchryx-token", "vouchryx"
	good := func(c string) map[string]any {
		return map[string]any{"jwk": k.jwk, "challenge": c, "proof_b64": k.proof(t, name, who, c), "lifetime_s": 3600}
	}
	enc := func(m map[string]any) string { b, _ := json.Marshal(m); return string(b) }
	edit := func(f func(m map[string]any)) func(string) string {
		return func(c string) string { m := good(c); f(m); return enc(m) }
	}
	cases := map[string]func(c string) string{
		"empty":            func(string) string { return "" },
		"not JSON":         func(string) string { return "{" },
		"an array":         func(string) string { return "[]" },
		"two objects":      func(c string) string { return enc(good(c)) + enc(good(c)) },
		"an unknown field": edit(func(m map[string]any) { m["not_before"] = 0 }),
		"no jwk":           edit(func(m map[string]any) { delete(m, "jwk") }),
		"a jwk with d": edit(func(m map[string]any) {
			m["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": k.jwk["x"], "y": k.jwk["y"], "d": "AAAA"}
		}),
		"a jwk as a string":   edit(func(m map[string]any) { m["jwk"] = "EC" }),
		"no challenge":        edit(func(m map[string]any) { delete(m, "challenge") }),
		"no proof":            edit(func(m map[string]any) { delete(m, "proof_b64") }),
		"a proof not base64":  edit(func(m map[string]any) { m["proof_b64"] = "***" }),
		"a proof cut short":   edit(func(m map[string]any) { m["proof_b64"] = m["proof_b64"].(string)[:20] }),
		"a life as a string":  edit(func(m map[string]any) { m["lifetime_s"] = "3600" }),
		"a negative life":     edit(func(m map[string]any) { m["lifetime_s"] = -1 }),
		"a fractional life":   edit(func(m map[string]any) { m["lifetime_s"] = 3600.5 }),
		"a life over the cap": edit(func(m map[string]any) { m["lifetime_s"] = 73 * 3600 }),
		"a body over the cap": edit(func(m map[string]any) { m["challenge"] = strings.Repeat("c", 64<<10) }),
	}
	for what, body := range cases {
		c := s.challenge(t, name, "", vouchryxSecret)
		w, out := s.do(t, "POST", "/v1/keys/"+name+"/delegate", body(c), "", vouchryxSecret)
		if w.Code < 400 || w.Code >= 500 || out["statement"] != nil {
			t.Errorf("%s: %d %v", what, w.Code, out)
		}
	}
	r := mrand.New(mrand.NewPCG(20261018, 9))
	alphabet := []byte(`{}[]",:=+/ABCabc019_- ` + "\x00\xff")
	for i := 0; i < 1500; i++ {
		c := s.challenge(t, name, "", vouchryxSecret)
		b := []byte(enc(good(c)))
		for n := 0; n <= r.IntN(4); n++ {
			b[r.IntN(len(b))] = alphabet[r.IntN(len(alphabet))]
		}
		w, out := s.do(t, "POST", "/v1/keys/"+name+"/delegate", string(b), "", vouchryxSecret)
		if w.Code >= 500 {
			t.Fatalf("case %d: %d for %q", i, w.Code, b)
		}
		if w.Code == http.StatusOK && out["kid"] != k.kid {
			t.Fatalf("case %d: an edited request certified %v, not the key that proved itself", i, out["kid"])
		}
	}
}

func TestAStatementIsNotAnsweredWhenItsUseCouldNotBeLogged(t *testing.T) {
	s := newDelegationStand(t)
	first := newOwnKey(t)
	c := s.challenge(t, "vouchryx-token", "", vouchryxSecret)
	if w, _ := s.do(t, "POST", "/v1/keys/vouchryx-token/delegate", delegateBody(t, first, "vouchryx-token", "vouchryx", c, 3600), "", vouchryxSecret); w.Code != http.StatusOK {
		t.Fatalf("control: %d", w.Code)
	}
	_ = s.srv.Log.Close()
	k := newOwnKey(t)
	c = s.challenge(t, "vouchryx-token", "", vouchryxSecret)
	w, body := s.do(t, "POST", "/v1/keys/vouchryx-token/delegate", delegateBody(t, k, "vouchryx-token", "vouchryx", c, 3600), "", vouchryxSecret)
	if w.Code != http.StatusServiceUnavailable || body["statement"] != nil {
		t.Fatalf("a statement with no record of it: %d %v", w.Code, body)
	}
	if s.jwksKids(t, "vouchryx-token")[k.kid] {
		t.Fatal("a key whose certification is not on the record is published")
	}
	if w, _ := s.do(t, "GET", "/v1/statements/"+k.kid, "", "", ""); w.Code != http.StatusNotFound {
		t.Fatalf("its statement is served: %d", w.Code)
	}
}

func TestTheRootKeySetCarriesBothHalves(t *testing.T) {
	s := newDelegationStand(t)
	kinds := func() map[string]int {
		w, body := s.do(t, "GET", "/v1/jwks/"+statement.RootName, "", "", "")
		if w.Code != http.StatusOK {
			t.Fatalf("the root key set: %d", w.Code)
		}
		out := map[string]int{}
		for _, k := range body["keys"].([]any) {
			m := k.(map[string]any)
			out[m["kty"].(string)+" "+m["alg"].(string)]++
		}
		return out
	}
	if got := kinds(); got["EC ES384"] != 1 || got["AKP ML-DSA-65"] != 1 || len(got) != 2 {
		t.Fatalf("the root key set holds %v, want one ES384 and one ML-DSA-65 key", got)
	}
	if w, _ := s.do(t, "POST", "/v1/keys/"+statement.RootName+"/rotate", "", "", adminSecret); w.Code != http.StatusOK {
		t.Fatalf("rotating the root: %d", w.Code)
	}
	if got := kinds(); got["EC ES384"] != 2 || got["AKP ML-DSA-65"] != 2 {
		t.Fatalf("after a rotation the root key set holds %v, want both halves of the active and the next root", got)
	}
	if w, _ := s.do(t, "POST", "/v1/keys/"+statement.RootName+"/rotate", "", "", adminSecret); w.Code != http.StatusConflict {
		t.Fatalf("a second root rotation while one is pending: %d", w.Code)
	}
	if w, _ := s.do(t, "POST", "/v1/keys/"+statement.RootName+"/rotate", "", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("a root rotation with no admin key: %d", w.Code)
	}
}

func TestAnAdminRevokesADelegatedKey(t *testing.T) {
	s := newDelegationStand(t)
	k := newOwnKey(t)
	c := s.challenge(t, "vouchryx-token", "", vouchryxSecret)
	if w, _ := s.do(t, "POST", "/v1/keys/vouchryx-token/delegate", delegateBody(t, k, "vouchryx-token", "vouchryx", c, 3600), "", vouchryxSecret); w.Code != http.StatusOK {
		t.Fatalf("control: %d", w.Code)
	}
	if !s.jwksKids(t, "vouchryx-token")[k.kid] {
		t.Fatal("control: the key is not published")
	}
	if w, _ := s.do(t, "POST", "/v1/kids/"+k.kid+"/revoke", "", "", vouchryxSecret); w.Code != http.StatusUnauthorized {
		t.Fatalf("a consumer revoked a key: %d", w.Code)
	}
	if w, _ := s.do(t, "POST", "/v1/kids/"+k.kid+"/revoke", "", "", adminSecret); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	if s.jwksKids(t, "vouchryx-token")[k.kid] {
		t.Fatal("a revoked delegated key is still published")
	}
	w, served := s.do(t, "GET", "/v1/statements/"+k.kid, "", "", "")
	if w.Code != http.StatusOK || served["revoked_at"] != float64(s.now.Unix()) {
		t.Fatalf("the revoked statement: %d %v", w.Code, served)
	}
	lines := s.logLines(t)
	if last := lines[len(lines)-1]; !strings.Contains(last, `"op":"revoke"`) || !strings.Contains(last, `"kid":"`+k.kid+`"`) || !strings.Contains(last, `"consumer":"admin:`) {
		t.Fatalf("the revocation is not on the log: %v", lines)
	}
}
