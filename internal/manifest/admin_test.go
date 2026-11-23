package manifest_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
)

// The built binary: an operator on the machine rotates and revokes through
// `keyryx admin`, nothing over the network does, and each change reaches the
// bus as an agent-event custody signs nothing for (invariant 43).
func TestTheBuiltCustodyRotatesAndRevokesThroughItsAdminSocketAndTellsTheBus(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the binary")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the admin socket reads its peer's credentials on Linux only")
	}
	_, r := load(t)
	bin := buildBinary(t, r)
	dir := shortDir(t)
	data := filepath.Join(dir, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	rootFile := filepath.Join(dir, "root.key")
	if err := os.WriteFile(rootFile, []byte(strings.Repeat("3d", 32)), 0o400); err != nil {
		t.Fatal(err)
	}
	cs := sha256.Sum256([]byte(consumerSecret))
	pol := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(pol, []byte(`{"version":1,"keys":[{"name":"wardryx-approval","alg":"ES256"}],
 "consumers":[{"name":"wardryx","auth":{"key_digest":"sha256:`+hex.EncodeToString(cs[:])+`"},"grants":{"wardryx-approval":["sign"]}}]}`), 0o400); err != nil {
		t.Fatal(err)
	}
	bus := filepath.Join(dir, "keyryx-custody.ndjson")
	addr := freeAddr(t)
	vars := map[string]string{"KEYRYX_DATA": data, "KEYRYX_ROOT_KEY_FILE": rootFile, "KEYRYX_POLICY": pol, "KEYRYX_ADDR": addr,
		"KEYRYX_EVENTS": bus, "KEYRYX_PUBLISH_AHEAD": "1m"}
	env := envList(vars)

	// A network admin key in the environment refuses the start.
	withKey := exec.Command(bin, "custody")
	withKey.Env = append(append([]string(nil), env...), "KEYRYX_ADMIN_KEYS=sha256:"+strings.Repeat("ab", 32))
	out, _ := withKey.CombinedOutput()
	if withKey.ProcessState.ExitCode() != 2 || !strings.Contains(string(out), "KEYRYX_ADMIN_KEYS") {
		t.Fatalf("an admin key in the environment: exit %d, %s", withKey.ProcessState.ExitCode(), out)
	}

	cmd := exec.Command(bin, "custody")
	cmd.Env = env
	stderr := &lockedBuffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if !waitFor(addr, 10*time.Second) {
		t.Fatalf("custody never listened: %s", stderr.String())
	}
	info, err := os.Stat(filepath.Join(data, "admin.sock"))
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("the admin socket: %v %v", info, err)
	}
	// One request to a connection: custody closes it after answering.
	sock := filepath.Join(data, "admin.sock")
	direct := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
	resp, err := direct.Post("http://keyryx-admin/v1/keys/no-such-key/rotate", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || !resp.Close {
		t.Fatalf("the admin socket answered %d and kept the connection open: %v", resp.StatusCode, !resp.Close)
	}
	state := func() map[string]any {
		resp, err := http.Get("http://" + addr + "/v1/state")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}
	old := state()["keys"].([]any)[0].(map[string]any)["active_kid"].(string)

	// Over the network, with any credential, there is no such route.
	for _, p := range []string{"/v1/keys/wardryx-approval/rotate", "/v1/kids/" + old + "/revoke"} {
		req, _ := http.NewRequest("POST", "http://"+addr+p, nil)
		req.Header.Set("Authorization", "Bearer "+consumerSecret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s over the network answered %d", p, resp.StatusCode)
		}
	}

	admin := func(args ...string) (int, string) {
		c := exec.Command(bin, append([]string{"admin"}, args...)...)
		c.Env = env
		var o bytes.Buffer
		c.Stdout = &o
		c.Stderr = &o
		_ = c.Run()
		return c.ProcessState.ExitCode(), o.String()
	}
	code, answer := admin("rotate", "wardryx-approval")
	if code != 0 {
		t.Fatalf("keyryx admin rotate: exit %d, %s", code, answer)
	}
	var rotated map[string]any
	_ = json.Unmarshal([]byte(answer), &rotated)
	next, _ := rotated["kid"].(string)
	if next == "" || next == old {
		t.Fatalf("the rotation answered %s", answer)
	}
	if code, answer := admin("revoke", next); code != 0 {
		t.Fatalf("keyryx admin revoke: exit %d, %s", code, answer)
	}
	if code, _ := admin("rotate", "no-such-key"); code != 1 {
		t.Fatalf("rotating an undeclared key: exit %d", code)
	}

	// The bus hears both, in order, as one chain from custody's subject.
	deadline := time.Now().Add(10 * time.Second)
	var lines []string
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(bus)
		lines = strings.Split(strings.TrimSpace(string(raw)), "\n")
		if len(lines) == 2 && lines[0] != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(lines) != 2 {
		t.Fatalf("the bus holds %d announcements, want 2: %q", len(lines), lines)
	}
	raw, _ := os.ReadFile(bus)
	if rep, err := event.VerifyChain(bytes.NewReader(raw)); err != nil || !rep.Ok() {
		t.Fatalf("the announcements are not one chain: %v %+v", err, rep)
	}
	want := []struct{ typ, sev, kid, prev string }{{"key_rotated", "info", next, old}, {"key_revoked", "high", next, ""}}
	for i, l := range lines {
		e, err := event.Unmarshal([]byte(l))
		if err != nil {
			t.Fatal(err)
		}
		if e.Source != "keyryx" || e.AgentID != "agent://keyryx.internal/custody" || e.Type != want[i].typ || e.Severity != want[i].sev ||
			e.Data["kid"] != want[i].kid || e.Data["name"] != "wardryx-approval" || e.Data["alg"] != "ES256" {
			t.Errorf("announcement %d: %s", i+1, l)
		}
		if want[i].typ == "key_rotated" && e.Data["previous_kid"] != want[i].prev {
			t.Errorf("the rotation names %v as the key it replaced, want %s", e.Data["previous_kid"], want[i].prev)
		}
	}
	if n := state()["unannounced"]; n != float64(0) {
		t.Fatalf("custody says %v changes wait for the bus after delivery", n)
	}
	use, _ := os.ReadFile(filepath.Join(data, "use.ndjson"))
	if !bytes.Contains(use, []byte(`"consumer":"admin:uid=`)) {
		t.Fatalf("the use log does not name the uid that asked: %s", use)
	}
}
