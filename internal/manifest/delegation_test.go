package manifest_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/policy"
)

const delegateSecret = "manifest-delegate-key-0123456789"

// The built binary, as a launcher runs it, certifying a key the consumer
// holds: a challenge, a proof, a statement both halves of the root signed, a
// key set the estate's shared verifier reads, and all of it still there after
// a SIGKILL and a restart.
func TestTheBuiltCustodyCertifiesADelegatedKeyAndKeepsItAcrossARestart(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the binary")
	}
	_, r := load(t)
	bin := buildBinary(t, r)
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	rootFile := filepath.Join(dir, "root.key")
	if err := os.WriteFile(rootFile, []byte(strings.Repeat("6b", 32)), 0o400); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(delegateSecret))
	pol := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(pol, []byte(`{"version":1,
 "keys":[{"name":"vouchryx-token","alg":"ES256","mode":"delegated","max_lifetime":"72h"}],
 "consumers":[{"name":"vouchryx","auth":{"key_digest":"sha256:`+hex.EncodeToString(sum[:])+`"},"grants":{"vouchryx-token":["delegate"]}}]}`), 0o400); err != nil {
		t.Fatal(err)
	}
	addr := freeAddr(t)
	env := envList(map[string]string{"KEYRYX_DATA": data, "KEYRYX_ROOT_KEY_FILE": rootFile, "KEYRYX_POLICY": pol, "KEYRYX_ADDR": addr})
	start := func() *exec.Cmd {
		cmd := exec.Command(bin, "custody")
		cmd.Env = env
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		if !waitFor(addr, 10*time.Second) {
			_ = cmd.Process.Kill()
			t.Fatalf("custody never listened on %s: %s", addr, stderr.String())
		}
		return cmd
	}
	call := func(method, path, body string) (int, map[string]any) {
		req, _ := http.NewRequest(method, "http://"+addr+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+delegateSecret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	keySet := func(name string) delegation.Set {
		resp, err := http.Get("http://" + addr + "/v1/jwks/" + name)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var set delegation.Set
		_ = json.NewDecoder(resp.Body).Decode(&set)
		return set
	}

	first := start()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j := delegation.FromPublic(&k.PublicKey, "")
	kid, _ := delegation.Thumbprint(j)
	code, ch := call("POST", "/v1/keys/vouchryx-token/challenge", "")
	if code != http.StatusOK {
		_ = first.Process.Kill()
		t.Fatalf("challenge: %d %v", code, ch)
	}
	challenge, _ := ch["challenge"].(string)
	in := append([]byte("keyryx/delegate/v1\x00vouchryx-token\x00vouchryx\x00"+kid+"\x00"), challenge...)
	d := sha256.Sum256(in)
	rr, ss, _ := ecdsa.Sign(rand.Reader, k, d[:])
	proof := base64.StdEncoding.EncodeToString(append(rr.FillBytes(make([]byte, 32)), ss.FillBytes(make([]byte, 32))...))
	body, _ := json.Marshal(map[string]any{"jwk": map[string]string{"kty": j.Kty, "crv": j.Crv, "x": j.X, "y": j.Y}, "challenge": challenge, "proof_b64": proof, "lifetime_s": 86400})
	code, ans := call("POST", "/v1/keys/vouchryx-token/delegate", string(body))
	if code != http.StatusOK || ans["kid"] != kid {
		_ = first.Process.Kill()
		t.Fatalf("delegate: %d %v", code, ans)
	}
	stmt, _ := json.Marshal(ans["statement"])
	tok, _ := delegation.SignES256(k, kid, map[string]any{"sub": "agent://acme.example/one"})
	if _, err := delegation.VerifyToken(tok, keySet("vouchryx-token")); err != nil {
		_ = first.Process.Kill()
		t.Fatalf("before the restart the shared verifier refused the certified key: %v", err)
	}
	_ = first.Process.Kill()
	_ = first.Wait()

	second := start()
	defer func() { _ = second.Process.Kill(); _ = second.Wait() }()
	if _, err := delegation.VerifyToken(tok, keySet("vouchryx-token")); err != nil {
		t.Fatalf("after the restart the certified key is not published: %v", err)
	}
	resp, err := http.Get("http://" + addr + "/v1/statements/" + kid)
	if err != nil {
		t.Fatal(err)
	}
	var served struct {
		Statement json.RawMessage `json:"statement"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&served)
	_ = resp.Body.Close()
	if !bytes.Equal(bytes.TrimSpace(served.Statement), stmt) {
		t.Fatalf("after the restart the statement served differs from the one issued")
	}
	// Both halves of the statement, against the root's published key set.
	var js struct {
		Payload    string `json:"payload"`
		Signatures []struct {
			Protected string `json:"protected"`
			Signature string `json:"signature"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(stmt, &js); err != nil || len(js.Signatures) != 2 {
		t.Fatalf("the statement is not two-signature JWS JSON: %v", err)
	}
	if _, err := delegation.VerifyToken(js.Signatures[0].Protected+"."+js.Payload+"."+js.Signatures[0].Signature, keySet("keyryx.delegation-root")); err != nil {
		t.Fatalf("the classical half does not verify under the published root: %v", err)
	}
	resp, err = http.Get("http://" + addr + "/v1/jwks/keyryx.delegation-root")
	if err != nil {
		t.Fatal(err)
	}
	var roots struct {
		Keys []map[string]string `json:"keys"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&roots)
	_ = resp.Body.Close()
	hdr, _ := base64.RawURLEncoding.DecodeString(js.Signatures[1].Protected)
	var h struct{ Kid string }
	_ = json.Unmarshal(hdr, &h)
	verified := false
	for _, key := range roots.Keys {
		if key["kty"] == "AKP" && key["kid"] == h.Kid {
			pub, _ := base64.RawURLEncoding.DecodeString(key["pub"])
			sig, _ := base64.RawURLEncoding.DecodeString(js.Signatures[1].Signature)
			if err := keystore.Verify(policy.MLDSA65, pub, []byte(js.Signatures[1].Protected+"."+js.Payload), sig); err != nil {
				t.Fatalf("the ML-DSA half does not verify under the published root: %v", err)
			}
			verified = true
		}
	}
	if !verified {
		t.Fatalf("the published root key set holds no ML-DSA key %s", h.Kid)
	}
}
