package manifest_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const stateAdminSecret = "manifest-admin-key-0123456789"

// lockedBuffer is a buffer a child process writes into while the test reads it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *lockedBuffer) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b.Reset()
}

// The built binary, with a key an operator revoked and somebody then edited
// back on disk: after a restart the key stays out of the key set, the state
// route names it, stderr says ALARM, and the use log holds the alarm.
func TestTheBuiltCustodyKeepsAnEditedBackKeyOutAndSaysSo(t *testing.T) {
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
	if err := os.WriteFile(rootFile, []byte(strings.Repeat("7c", 32)), 0o400); err != nil {
		t.Fatal(err)
	}
	cs := sha256.Sum256([]byte(consumerSecret))
	as := sha256.Sum256([]byte(stateAdminSecret))
	pol := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(pol, []byte(`{"version":1,"keys":[{"name":"wardryx-approval","alg":"ES256"}],
 "consumers":[{"name":"wardryx","auth":{"key_digest":"sha256:`+hex.EncodeToString(cs[:])+`"},"grants":{"wardryx-approval":["sign"]}}]}`), 0o400); err != nil {
		t.Fatal(err)
	}
	addr := freeAddr(t)
	env := envList(map[string]string{"KEYRYX_DATA": data, "KEYRYX_ROOT_KEY_FILE": rootFile, "KEYRYX_POLICY": pol, "KEYRYX_ADDR": addr,
		"KEYRYX_ADMIN_KEYS": "sha256:" + hex.EncodeToString(as[:]), "KEYRYX_PUBLISH_AHEAD": "1m"})
	stderr := &lockedBuffer{}
	start := func() *exec.Cmd {
		cmd := exec.Command(bin, "custody")
		cmd.Env = env
		stderr.Reset()
		cmd.Stderr = stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		if !waitFor(addr, 10*time.Second) {
			_ = cmd.Process.Kill()
			t.Fatalf("custody never listened: %s", stderr.String())
		}
		return cmd
	}
	call := func(method, path, bearer string) (int, map[string]any) {
		req, _ := http.NewRequest(method, "http://"+addr+path, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	kids := func() map[string]bool {
		_, body := call("GET", "/v1/jwks/wardryx-approval", "")
		out := map[string]bool{}
		keys, _ := body["keys"].([]any)
		for _, k := range keys {
			out[k.(map[string]any)["kid"].(string)] = true
		}
		return out
	}

	first := start()
	_, st := call("GET", "/v1/state", "")
	old := st["keys"].([]any)[0].(map[string]any)["active_kid"].(string)
	if code, _ := call("POST", "/v1/keys/wardryx-approval/rotate", stateAdminSecret); code != http.StatusOK {
		_ = first.Process.Kill()
		t.Fatalf("rotate: %d", code)
	}
	if code, _ := call("POST", "/v1/kids/"+old+"/revoke", stateAdminSecret); code != http.StatusOK {
		_ = first.Process.Kill()
		t.Fatalf("revoke: %d", code)
	}
	if kids()[old] {
		_ = first.Process.Kill()
		t.Fatal("control: the revoked key is published")
	}
	_ = first.Process.Kill()
	_ = first.Wait()

	path := filepath.Join(data, "keys", "wardryx-approval", old+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	_ = json.Unmarshal(raw, &rec)
	rec["state"], rec["revoked"] = "retired", 0
	edited, _ := json.Marshal(rec)
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}

	second := start()
	defer func() { _ = second.Process.Kill(); _ = second.Wait() }()
	if kids()[old] {
		t.Fatal("after the edit and a restart, the revoked key is published again")
	}
	_, st = call("GET", "/v1/state", "")
	found := false
	alarms, _ := st["alarms"].([]any)
	for _, a := range alarms {
		if a.(map[string]any)["kid"] == old {
			found = true
		}
	}
	if !found {
		t.Fatalf("the state route names no alarm for %s: %v", old, st["alarms"])
	}
	if !strings.Contains(stderr.String(), "ALARM") || !strings.Contains(stderr.String(), old) {
		t.Fatalf("stderr does not say ALARM for %s: %s", old, stderr.String())
	}
	log, _ := os.ReadFile(filepath.Join(data, "use.ndjson"))
	if !bytes.Contains(log, []byte(`"op":"state_alarm"`)) || !bytes.Contains(log, []byte(old)) {
		t.Fatalf("the use log holds no alarm for %s", old)
	}
}
