package witnessapi

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/merkle"
	"github.com/TAIPANBOX/keyryx/internal/statement"
	"github.com/TAIPANBOX/keyryx/internal/wlog"
)

// What a verifier holding an old tree head asks the witness: is this entry
// in the log, and is today's log an extension of the one I saw.

var t0 = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func stand(t *testing.T) (*Server, *wlog.Log, []wlog.Head) {
	t.Helper()
	now := t0
	clock := func() time.Time { return now }
	kd := filepath.Join(t.TempDir(), "keys")
	_ = os.Mkdir(kd, 0o700)
	store, err := keystore.Open(kd, [32]byte{4, 4}, wlog.Keys, clock)
	if err != nil {
		t.Fatal(err)
	}
	l, err := wlog.Open(t.TempDir(), statement.StoreKeys(store, wlog.KeyES384, wlog.KeyMLDSA), clock)
	if err != nil {
		t.Fatal(err)
	}
	var heads []wlog.Head
	for round, n := range []int{3, 4, 6} {
		var es []wlog.Entry
		for i := 0; i < n; i++ {
			es = append(es, wlog.Entry{Kind: "stream", SeenAt: now.Unix(), Stream: fmt.Sprintf("s%d.ndjson", i), Lines: int64(round*10 + i)})
		}
		if err := l.Append(es...); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
		h, err := l.Sign(store)
		if err != nil {
			t.Fatal(err)
		}
		heads = append(heads, h)
	}
	return &Server{Log: l, Store: store}, l, heads
}

func get(t *testing.T, h http.Handler, path string) (int, map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://witness.test"+path, nil))
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func hashOf(t *testing.T, s any) merkle.Hash {
	t.Helper()
	b, err := hex.DecodeString(fmt.Sprint(s))
	if err != nil || len(b) != 48 {
		t.Fatalf("not a hash: %v", s)
	}
	var h merkle.Hash
	copy(h[:], b)
	return h
}

func proofOf(t *testing.T, v any) []merkle.Hash {
	t.Helper()
	var out []merkle.Hash
	list, _ := v.([]any)
	for _, p := range list {
		out = append(out, hashOf(t, p))
	}
	return out
}

func TestTheWitnessRoutesServeProofsThatVerify(t *testing.T) {
	srv, l, heads := stand(t)
	h := srv.Handler()
	code, head := get(t, h, "/v1/witness/head")
	last := heads[len(heads)-1]
	if code != http.StatusOK || head["size"] != float64(last.Size) || head["root"] != last.Root {
		t.Fatalf("head: %d %v", code, head)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://witness.test/v1/witness/keys", nil))
	keys, err := statement.KeysFromJWKS(w.Body.Bytes())
	if err != nil {
		t.Fatalf("the witness's key set: %v", err)
	}
	root := hashOf(t, last.Root)
	for _, half := range []wlog.Sig{last.ES384, last.MLDSA65} {
		alg, pub, ok := keys(half.Kid)
		sig, _ := hexOrB64(half.Sig)
		if !ok || keystore.Verify(alg, pub, wlog.HeadInput(last.Size, root, last.At), sig) != nil {
			t.Fatalf("the head's %s half does not verify under the published key set", alg)
		}
	}
	for i := 0; i < int(last.Size); i++ {
		code, p := get(t, h, fmt.Sprintf("/v1/witness/inclusion?index=%d&size=%d", i, last.Size))
		if code != http.StatusOK || !merkle.VerifyInclusion(hashOf(t, p["leaf"]), i, int(last.Size), proofOf(t, p["proof"]), root) {
			t.Fatalf("inclusion of %d: %d %v", i, code, p)
		}
	}
	first := heads[0]
	code, c := get(t, h, fmt.Sprintf("/v1/witness/consistency?first=%d&second=%d", first.Size, last.Size))
	if code != http.StatusOK || !merkle.VerifyConsistency(int(first.Size), int(last.Size), proofOf(t, c["proof"]), hashOf(t, first.Root), root) {
		t.Fatalf("consistency: %d %v", code, c)
	}
	code, e := get(t, h, "/v1/witness/entries?start=2&end=5")
	entries, _ := e["entries"].([]any)
	if code != http.StatusOK || len(entries) != 3 {
		t.Fatalf("entries: %d %v", code, e)
	}
	for i, en := range entries {
		b, _ := json.Marshal(en)
		var want wlog.Entry
		_ = json.Unmarshal(b, &want)
		if want.Lines != l.Entries()[2+i].Lines {
			t.Fatalf("entry %d: %v", 2+i, en)
		}
	}
}

func TestHostileProofQueriesAreRefusedAndNeverPanic(t *testing.T) {
	srv, _, heads := stand(t)
	h := srv.Handler()
	n := heads[len(heads)-1].Size
	for _, q := range []string{
		"/v1/witness/inclusion", "/v1/witness/inclusion?index=-1&size=3", "/v1/witness/inclusion?index=3&size=3",
		fmt.Sprintf("/v1/witness/inclusion?index=0&size=%d", n+1), "/v1/witness/inclusion?index=x&size=3",
		"/v1/witness/inclusion?index=0&size=99999999999999999999", "/v1/witness/inclusion?index=0&size=0",
		"/v1/witness/consistency?first=0&second=3", "/v1/witness/consistency?first=4&second=3",
		fmt.Sprintf("/v1/witness/consistency?first=1&second=%d", n+1), "/v1/witness/consistency?first=&second=",
		"/v1/witness/entries?start=5&end=2", "/v1/witness/entries?start=0&end=100000", "/v1/witness/entries?start=-1&end=2",
		fmt.Sprintf("/v1/witness/entries?start=0&end=%d", n+1),
	} {
		if code, body := get(t, h, q); code != http.StatusBadRequest || body["proof"] != nil || body["entries"] != nil {
			t.Errorf("%s: %d %v", q, code, body)
		}
	}
}

func TestTheWitnessRouteTableIsTheMux(t *testing.T) {
	srv, _, _ := stand(t)
	h := srv.Handler()
	routes := Routes()
	if len(routes) == 0 {
		t.Fatal("no route is declared, so this test measured nothing")
	}
	for _, r := range routes {
		code, _ := get(t, h, r.Pattern)
		if code == http.StatusNotFound || code == http.StatusMethodNotAllowed || code >= 500 {
			t.Errorf("%s %s is declared and answered %d", r.Method, r.Pattern, code)
		}
		if r.Method != "GET" {
			t.Errorf("%s %s: the witness answers reads only", r.Method, r.Pattern)
		}
	}
	for _, p := range []string{"/", "/v1", "/v1/witness", "/v1/witness/sign", "/debug/pprof/"} {
		if code, _ := get(t, h, p); code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s is served though no route names it: %d", p, code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "http://witness.test/v1/witness/head", strings.NewReader("{}")))
	if w.Code != http.StatusMethodNotAllowed && w.Code != http.StatusNotFound {
		t.Errorf("POST to the head answered %d", w.Code)
	}
}

func hexOrB64(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return hex.DecodeString(s)
}
