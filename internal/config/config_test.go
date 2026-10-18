package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// What custody believes about its own environment. Every value is a statement
// about which keys it holds and who may use them, so a missing or malformed
// one refuses the start (CLAUDE.md invariant 6).

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writeFile(t *testing.T, dir, name, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

const socketPolicy = `{"version":1,"keys":[{"name":"wardryx-approval","alg":"ES256"}],
 "consumers":[{"name":"wardryx","auth":{"socket":"wardryx"},"grants":{"wardryx-approval":["sign"]}}]}`

const keyPolicy = `{"version":1,"keys":[{"name":"wardryx-approval","alg":"ES256"}],
 "consumers":[{"name":"wardryx","auth":{"key_digest":"` + "sha256:0000000000000000000000000000000000000000000000000000000000000001" + `"},"grants":{"wardryx-approval":["sign"]}}]}`

const k8sPolicy = `{"version":1,"keys":[{"name":"cloud-audit","alg":"ES256"}],
 "consumers":[{"name":"cloud","auth":{"k8s":{"issuer":"https://k3s.acme.example","subject":"system:serviceaccount:a:b"}},"grants":{"cloud-audit":["sign"]}}]}`

// base is a complete environment with a socket consumer.
func base(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	sockets := filepath.Join(dir, "sock")
	if err := os.MkdirAll(filepath.Join(sockets, "wardryx"), 0o770); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(sockets, 0o750)
	_ = os.Chmod(filepath.Join(sockets, "wardryx"), 0o770)
	return map[string]string{
		"KEYRYX_DATA":          data,
		"KEYRYX_ROOT_KEY_FILE": writeFile(t, dir, "root.key", strings.Repeat("ab", 32)+"\n", 0o400),
		"KEYRYX_POLICY":        writeFile(t, dir, "policy.json", socketPolicy, 0o400),
		"KEYRYX_SOCKET_DIR":    sockets,
	}
}

func withEnv(t *testing.T, env map[string]string) (Config, error) {
	t.Helper()
	for _, k := range []string{"KEYRYX_DATA", "KEYRYX_ROOT_KEY_FILE", "KEYRYX_POLICY", "KEYRYX_ADDR", "KEYRYX_SOCKET_DIR", "KEYRYX_ADMIN_KEYS", "KEYRYX_K8S_ISSUERS", "KEYRYX_PUBLISH_AHEAD"} {
		t.Setenv(k, env[k])
	}
	return FromEnv()
}

func TestAFullConfigComesUp(t *testing.T) {
	env := base(t)
	env["KEYRYX_ADMIN_KEYS"] = digest("admin")
	env["KEYRYX_PUBLISH_AHEAD"] = "30m"
	c, err := withEnv(t, env)
	if err != nil {
		t.Fatalf("a complete environment was refused: %v", err)
	}
	if c.Addr != DefaultAddr || c.DataDir != env["KEYRYX_DATA"] || c.Policy == nil || len(c.AdminKeys) != 1 || c.PublishAhead != 30*time.Minute {
		t.Fatalf("config %+v", c)
	}
	if c.Root == [32]byte{} {
		t.Fatal("the root key did not load")
	}
	if DefaultAddr != "127.0.0.1:4340" {
		t.Fatalf("the default address is %s; loopback on 4340 is the one the estate's port map reserves", DefaultAddr)
	}
	env["KEYRYX_PUBLISH_AHEAD"] = ""
	if c, err := withEnv(t, env); err != nil || c.PublishAhead != 15*time.Minute {
		t.Fatalf("unset publish-ahead: %v %v, want 15m", c.PublishAhead, err)
	}
}

func TestEachRequiredVariableIsNamedWhenMissing(t *testing.T) {
	if _, err := withEnv(t, base(t)); err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, v := range []string{"KEYRYX_DATA", "KEYRYX_ROOT_KEY_FILE", "KEYRYX_POLICY"} {
		env := base(t)
		env[v] = ""
		_, err := withEnv(t, env)
		if err == nil || !strings.Contains(err.Error(), v) {
			t.Errorf("%s unset: %v", v, err)
		}
	}
}

func TestAConsumerWhoseWayInIsNotConfiguredRefusesTheStart(t *testing.T) {
	env := base(t)
	env["KEYRYX_SOCKET_DIR"] = ""
	if _, err := withEnv(t, env); err == nil || !strings.Contains(err.Error(), "KEYRYX_SOCKET_DIR") {
		t.Errorf("a socket consumer with no socket directory: %v", err)
	}
	env = base(t)
	_ = os.RemoveAll(filepath.Join(env["KEYRYX_SOCKET_DIR"], "wardryx"))
	if _, err := withEnv(t, env); err == nil || !strings.Contains(err.Error(), "wardryx") {
		t.Errorf("a socket consumer whose directory is missing: %v", err)
	}
	env = base(t)
	_ = os.Chmod(filepath.Join(env["KEYRYX_SOCKET_DIR"], "wardryx"), 0o777)
	if _, err := withEnv(t, env); err == nil {
		t.Error("a socket directory any user can enter was accepted")
	}
	env = base(t)
	env["KEYRYX_POLICY"] = writeFile(t, t.TempDir(), "p.json", k8sPolicy, 0o400)
	if _, err := withEnv(t, env); err == nil || !strings.Contains(err.Error(), "KEYRYX_K8S_ISSUERS") {
		t.Errorf("a k8s consumer with no issuer configured: %v", err)
	}
	env = base(t)
	env["KEYRYX_POLICY"] = writeFile(t, t.TempDir(), "p.json", keyPolicy, 0o400)
	env["KEYRYX_SOCKET_DIR"] = ""
	if _, err := withEnv(t, env); err != nil {
		t.Errorf("control: a key consumer needs no socket directory: %v", err)
	}
}

func TestMalformedValuesRefuseTheStart(t *testing.T) {
	if _, err := withEnv(t, base(t)); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, edit := range map[string]func(map[string]string){
		"a publish-ahead that is not a duration": func(e map[string]string) { e["KEYRYX_PUBLISH_AHEAD"] = "soon" },
		"a publish-ahead under a minute":         func(e map[string]string) { e["KEYRYX_PUBLISH_AHEAD"] = "30s" },
		"a publish-ahead over a day":             func(e map[string]string) { e["KEYRYX_PUBLISH_AHEAD"] = "25h" },
		"an admin key in the clear":              func(e map[string]string) { e["KEYRYX_ADMIN_KEYS"] = "admin" },
		"a policy that does not parse":           func(e map[string]string) { e["KEYRYX_POLICY"] = writeFile(t, t.TempDir(), "p.json", "{", 0o400) },
		"a root key readable by the group": func(e map[string]string) {
			e["KEYRYX_ROOT_KEY_FILE"] = writeFile(t, t.TempDir(), "r.key", strings.Repeat("ab", 32), 0o440)
		},
		"a missing policy file":       func(e map[string]string) { e["KEYRYX_POLICY"] = filepath.Join(t.TempDir(), "absent.json") },
		"an address that is not one":  func(e map[string]string) { e["KEYRYX_ADDR"] = "not an address" },
		"a k8s issuer spec malformed": func(e map[string]string) { e["KEYRYX_K8S_ISSUERS"] = "https://k3s|aud" },
		"a policy file over one MiB": func(e map[string]string) {
			e["KEYRYX_POLICY"] = writeFile(t, t.TempDir(), "p.json", strings.Repeat(" ", 2<<20)+socketPolicy, 0o400)
		},
	} {
		env := base(t)
		edit(env)
		if _, err := withEnv(t, env); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
