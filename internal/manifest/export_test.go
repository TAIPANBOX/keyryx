package manifest_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/keyclient"
)

// The built custody copies what it certified into KEYRYX_STATEMENTS_DIR for a
// reader on the machine that may open no connection: the root key set, a
// certified key's statement soon after it is certified, and its revocation as
// part of the revocation (invariant 44).
func TestTheBuiltCustodyPublishesItsStatementsForAReaderOnTheMachine(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the binary")
	}
	_, r := load(t)
	bin := buildBinary(t, r)
	dir := shortDir(t)
	data := filepath.Join(dir, "data")
	pub := filepath.Join(dir, "statements")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(dir, "events")
	if err := os.Mkdir(events, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(pub, 0o755); err != nil {
		t.Fatal(err)
	}
	rootFile := filepath.Join(dir, "root.key")
	_ = os.WriteFile(rootFile, []byte(strings.Repeat("5e", 32)), 0o400)
	sum := sha256.Sum256([]byte(consumerSecret))
	pol := filepath.Join(dir, "policy.json")
	_ = os.WriteFile(pol, []byte(`{"version":1,
 "keys":[{"name":"wardryx-checkpoint","alg":"ES256","mode":"delegated","max_lifetime":"24h"}],
 "consumers":[{"name":"wardryx","auth":{"key_digest":"sha256:`+hex.EncodeToString(sum[:])+`"},"grants":{"wardryx-checkpoint":["delegate"]}}]}`), 0o400)
	addr := freeAddr(t)
	env := envList(map[string]string{"KEYRYX_DATA": data, "KEYRYX_ROOT_KEY_FILE": rootFile, "KEYRYX_POLICY": pol, "KEYRYX_ADDR": addr,
		"KEYRYX_EVENTS": filepath.Join(events, "keyryx-custody.ndjson"), "KEYRYX_STATEMENTS_DIR": pub})
	cmd := exec.Command(bin, "custody")
	cmd.Env = env
	var stderr lockedBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if !waitFor(addr, 10*time.Second) {
		t.Fatalf("custody never listened: %s", stderr.String())
	}
	root, err := os.ReadFile(filepath.Join(pub, "delegation-root.jwks.json"))
	if err != nil || !strings.Contains(string(root), `"ML-DSA-65"`) || !strings.Contains(string(root), `"ES384"`) {
		t.Fatalf("the root key set was not published at the start: %v %s", err, root)
	}
	bearer := filepath.Join(dir, "bearer")
	_ = os.WriteFile(bearer, []byte(consumerSecret), 0o600)
	var way keyclient.Credential
	way.BearerFile = bearer
	kc, err := keyclient.New(keyclient.Config{BaseURL: "http://" + addr, Consumer: "wardryx", Credential: way})
	if err != nil {
		t.Fatal(err)
	}
	d, err := kc.Delegated("wardryx-checkpoint", "ES256", 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.RenewIfDue(context.Background()); err != nil {
		t.Fatal(err)
	}
	k, _ := d.Current()
	file := filepath.Join(pub, k.Kid+".json")
	read := func() (json.RawMessage, int64, bool) {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, 0, false
		}
		var v struct {
			Statement json.RawMessage `json:"statement"`
			RevokedAt int64           `json:"revoked_at"`
		}
		if json.Unmarshal(raw, &v) != nil {
			return nil, 0, false
		}
		return v.Statement, v.RevokedAt, true
	}
	var st json.RawMessage
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if s, rev, ok := read(); ok && rev == 0 {
			st = s
			break
		}
	}
	if st == nil || string(st) != string(k.Statement) {
		t.Fatalf("the certified key's statement was not published: %s", stderr.String())
	}
	info, _ := os.Stat(file)
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("the copy is mode %o", info.Mode().Perm())
	}
	if runtime.GOOS != "linux" {
		return // the admin socket reads its peer's credentials on Linux only
	}
	a := exec.Command(bin, "admin", "revoke", k.Kid)
	a.Env = env
	if out, err := a.CombinedOutput(); err != nil {
		t.Fatalf("keyryx admin revoke: %v %s", err, out)
	}
	if _, rev, ok := read(); !ok || rev == 0 {
		t.Fatalf("the revocation was not in the copy when the command returned: %v %d", ok, rev)
	}
}
