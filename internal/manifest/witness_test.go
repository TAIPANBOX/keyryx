package manifest_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/keyryx/internal/wconfig"
)

func witnessEnv(t *testing.T) (map[string]string, string) {
	t.Helper()
	dir := t.TempDir()
	data := filepath.Join(dir, "witness")
	events := filepath.Join(dir, "events")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(events, 0o750); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "witness.key")
	if err := os.WriteFile(root, []byte(strings.Repeat("9e", 32)), 0o400); err != nil {
		t.Fatal(err)
	}
	addr := freeAddr(t)
	return map[string]string{
		"KEYRYX_WITNESS_DATA":          data,
		"KEYRYX_WITNESS_ROOT_KEY_FILE": root,
		"KEYRYX_WITNESS_EVENTS":        events,
		"KEYRYX_WITNESS_ADDR":          addr,
		"KEYRYX_WITNESS_INTERVAL":      "1s",
	}, addr
}

// Every variable the declaration says the witness requires, removed in turn,
// stops the built binary with the declared code and names the variable.
func TestTheBuiltWitnessRefusesWithoutEachRequiredVariable(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the binary")
	}
	m, r := load(t)
	c := m.Components[0]
	if c.Checked.WitnessListenDefault != wconfig.DefaultAddr {
		t.Fatalf("components.json says the witness listens on %s and the code on %s", c.Checked.WitnessListenDefault, wconfig.DefaultAddr)
	}
	bin := buildBinary(t, r)
	full, _ := witnessEnv(t)
	n := 0
	for k, spec := range c.Checked.Env {
		if !spec.Required || spec.Role != "witness" {
			continue
		}
		n++
		env := map[string]string{}
		for kk, vv := range full {
			if kk != k {
				env[kk] = vv
			}
		}
		cmd := exec.Command(bin, "witness")
		cmd.Env = envList(env)
		out, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != c.Checked.MissingRequiredExitCode || !strings.Contains(string(out), k) {
			t.Errorf("the witness without %s: %v %q", k, err, out)
		}
	}
	if n == 0 {
		t.Fatal("no variable is declared required for the witness, so this test measured nothing")
	}
}

// The built binary as a launcher runs the witness: it reads a stream, a
// rewrite of a line it saw (re-linked, so the chain alone accepts it) becomes
// an event in keyryx.ndjson, its tree heads are served, and after a SIGKILL
// `keyryx verify log` checks its log against its published keys, and refuses
// the log once it is edited.
func TestTheBuiltWitnessCatchesARewriteAndVerifyChecksItsLog(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the binary")
	}
	_, r := load(t)
	bin := buildBinary(t, r)
	env, addr := witnessEnv(t)
	stream := filepath.Join(env["KEYRYX_WITNESS_EVENTS"], "wardryx.ndjson")
	w, err := event.NewChainedWriter(stream)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_ = w.Write(event.Event{Schema: event.SchemaV10, TS: "2026-10-18T12:00:00Z", Source: "wardryx", Type: "policy_allow", AgentID: "agent://acme.example/one", Severity: "info"})
	}
	cmd := exec.Command(bin, "witness")
	cmd.Env = envList(env)
	var stderr lockedBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if !waitFor(addr, 10*time.Second) {
		t.Fatalf("the witness never listened: %s", stderr.String())
	}
	head := func() map[string]any {
		resp, err := http.Get("http://" + addr + "/v1/witness/head")
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
		var h map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&h)
		return h
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if h := head(); h != nil && h["size"] != nil && h["size"].(float64) > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if h := head(); h == nil || h["size"] == nil {
		t.Fatalf("no tree head was served: %s", stderr.String())
	}
	// Rewrite line 1 and re-link line 2: the chain alone accepts this.
	raw, _ := os.ReadFile(stream)
	ls := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	var m map[string]any
	_ = json.Unmarshal([]byte(ls[0]), &m)
	m["type"] = "policy_alloy" // the same length: a stream that shrank is a truncation finding
	b, _ := json.Marshal(m)
	ls[0] = string(b)
	h, _ := event.ChainHashRaw(b)
	var next map[string]any
	_ = json.Unmarshal([]byte(ls[1]), &next)
	next["prev_hash"] = h
	nb, _ := json.Marshal(next)
	ls[1] = string(nb)
	_ = os.WriteFile(stream, []byte(strings.Join(ls, "\n")+"\n"), 0o644)
	alerts := filepath.Join(env["KEYRYX_WITNESS_EVENTS"], "keyryx.ndjson")
	found := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline) && !found; time.Sleep(200 * time.Millisecond) {
		evs, _ := event.ReadFile(alerts)
		for _, e := range evs {
			if e.Type == "witness_stream_rewritten" && e.Data["stream"] == "wardryx.ndjson" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("the rewrite never reached keyryx.ndjson: %s", stderr.String())
	}
	resp, err := http.Get("http://" + addr + "/v1/witness/keys")
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	keysFile := filepath.Join(t.TempDir(), "witness-keys.json")
	_ = os.WriteFile(keysFile, keys, 0o644)
	_ = cmd.Process.Kill()
	_ = cmd.Wait()

	verify := func() (int, string) {
		v := exec.Command(bin, "verify", "log", "--dir", env["KEYRYX_WITNESS_DATA"], "--keys", keysFile)
		out, err := v.CombinedOutput()
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), string(out)
		}
		return 0, string(out)
	}
	if code, out := verify(); code != 0 || !strings.Contains(out, "VERIFIED") {
		t.Fatalf("keyryx verify log on the witness's own log: exit %d\n%s", code, out)
	}
	logPath := filepath.Join(env["KEYRYX_WITNESS_DATA"], "log.ndjson")
	lraw, _ := os.ReadFile(logPath)
	_ = os.WriteFile(logPath, bytes.Replace(lraw, []byte(`"kind":"stream"`), []byte(`"kind":"strean"`), 1), 0o600)
	if code, out := verify(); code != 1 || !strings.Contains(out, "NOT VERIFIED") {
		t.Fatalf("keyryx verify log on an edited log: exit %d\n%s", code, out)
	}
}
