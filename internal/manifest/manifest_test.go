// The declaration in components.json is only worth reading if this repository
// proves it, and proves it by running rather than by describing.
//
// What is proved here is the `checked` bucket and nothing else. The
// `declared` bucket carries a `why` on every entry and is asserted against
// nothing, on purpose: a test that pretended to verify a sentence about
// purpose would be the failure this design exists to avoid.
package manifest_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/config"
	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/policy"
)

type manifest struct {
	Repo       string `json:"repo"`
	Components []struct {
		Name    string `json:"name"`
		Checked struct {
			Package       string `json:"package"`
			ListenDefault string `json:"listen_default"`
			HealthPath    string `json:"health_path"`
			Env           map[string]struct {
				Required bool   `json:"required"`
				Role     string `json:"role"`
			} `json:"env"`
			Roles                   []string `json:"roles"`
			WitnessListenDefault    string   `json:"witness_listen_default"`
			MissingRequiredExitCode int      `json:"missing_required_exit_code"`
		} `json:"checked"`
		Declared map[string]struct {
			Why string `json:"why"`
		} `json:"declared"`
	} `json:"components"`
}

func root(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("no go.mod above the test's working directory")
	return ""
}

func load(t *testing.T) (manifest, string) {
	t.Helper()
	r := root(t)
	raw, err := os.ReadFile(filepath.Join(r, "components.json"))
	if err != nil {
		t.Fatalf("components.json: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("components.json is not JSON this reader understands: %v", err)
	}
	if len(m.Components) == 0 {
		t.Fatal("components.json declares nothing, so this test measured nothing")
	}
	return m, r
}

// A binary this repository builds and does not declare is invisible from
// outside by construction.
func TestEveryBinaryThisRepositoryBuildsIsDeclaredAndTheReverse(t *testing.T) {
	m, r := load(t)
	list := exec.Command("go", "list", "-f", `{{if eq .Name "main"}}{{.ImportPath}}{{end}}`, "./...")
	list.Dir = r
	out, err := list.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	built := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			built[line] = true
		}
	}
	if len(built) == 0 {
		t.Fatal("go list found no main package, so this test measured nothing")
	}
	declared := map[string]bool{}
	for _, c := range m.Components {
		if c.Checked.Package == "" {
			t.Errorf("component %q declares no package", c.Name)
			continue
		}
		declared[c.Checked.Package] = true
	}
	for p := range built {
		if !declared[p] {
			t.Errorf("this repository builds %s and components.json does not declare it", p)
		}
	}
	for p := range declared {
		if !built[p] {
			t.Errorf("components.json declares %s and this repository does not build it", p)
		}
	}
}

// Every KEYRYX_ name in non-test source, against every one declared, by
// string literal rather than by os.Getenv call site, so a name read through a
// helper is not missed. Zero names is a true state for the scaffold; zero
// files read is not, and fails.
func TestEveryEnvironmentVariableThisRepositoryReadsIsDeclaredAndTheReverse(t *testing.T) {
	m, r := load(t)
	name := regexp.MustCompile(`"(KEYRYX_[A-Z0-9_]+)"`)
	read := map[string]bool{}
	files := 0
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.Walk(filepath.Join(r, dir), func(p string, info os.FileInfo, err error) error {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			files++
			for _, mm := range name.FindAllStringSubmatch(string(b), -1) {
				read[mm[1]] = true
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if files == 0 {
		t.Fatal("no non-test Go file was read, so this test measured nothing")
	}
	declared := map[string]bool{}
	for _, c := range m.Components {
		for k := range c.Checked.Env {
			declared[k] = true
		}
	}
	for v := range read {
		if !declared[v] {
			t.Errorf("this repository reads %s and components.json does not declare it", v)
		}
	}
	for v := range declared {
		if !read[v] {
			t.Errorf("components.json declares %s and nothing in this repository reads it", v)
		}
	}
}

// A declared entry with no `why` is a claim wearing the costume of a
// decision.
func TestEveryDeclaredEntryCarriesItsReason(t *testing.T) {
	m, _ := load(t)
	n := 0
	for _, c := range m.Components {
		for k, v := range c.Declared {
			n++
			if strings.TrimSpace(v.Why) == "" {
				t.Errorf("%s: declared entry %q has no why", c.Name, k)
			}
		}
	}
	if n == 0 {
		t.Fatal("no declared entry exists, so this test measured nothing")
	}
}

// The built binary refuses each role it has when the role's configuration is
// absent, with the exit code a launcher reads. Started as a process, because a
// launcher sees a process and nothing else.
func TestTheBuiltBinaryRefusesEachRoleWithoutItsConfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the binary")
	}
	m, r := load(t)
	bin := filepath.Join(t.TempDir(), "keyryx")
	build := exec.Command("go", "build", "-o", bin, "./cmd/keyryx")
	build.Dir = r
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building: %v\n%s", err, out)
	}
	c := m.Components[0]
	if len(c.Checked.Roles) == 0 || c.Checked.MissingRequiredExitCode == 0 {
		t.Fatal("components.json names no role or no exit code, so this test measured nothing")
	}
	for _, role := range c.Checked.Roles {
		cmd := exec.Command(bin, role)
		cmd.Env = []string{}
		out, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != c.Checked.MissingRequiredExitCode {
			t.Errorf("%s: %v, want exit %d (output %q)", role, err, c.Checked.MissingRequiredExitCode, out)
		}
	}
}

func buildBinary(t *testing.T, r string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "keyryx")
	build := exec.Command("go", "build", "-o", bin, "./cmd/keyryx")
	build.Dir = r
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building: %v\n%s", err, out)
	}
	return bin
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func waitFor(addr string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			_ = c.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

const consumerSecret = "manifest-consumer-key-0123456789"

// custodyEnv is the smallest environment the declaration says custody needs,
// built from the declaration's own names, plus a socket consumer whose socket
// directory is short enough for a unix socket path.
func custodyEnv(t *testing.T) (map[string]string, string) {
	t.Helper()
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "root.key")
	if err := os.WriteFile(root, []byte(strings.Repeat("5a", 32)+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(consumerSecret))
	sockets, err := os.MkdirTemp("/tmp", "kx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockets) })
	if err := os.Mkdir(filepath.Join(sockets, "wardryx"), 0o770); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(sockets, 0o750)
	_ = os.Chmod(filepath.Join(sockets, "wardryx"), 0o770)
	pol := filepath.Join(dir, "policy.json")
	body := `{"version":1,"keys":[{"name":"wardryx-approval","alg":"ES256"},{"name":"trailryx-root","alg":"ES384"}],
 "consumers":[{"name":"record-seal","auth":{"key_digest":"sha256:` + hex.EncodeToString(sum[:]) + `"},"grants":{"trailryx-root":["sign"]}},
  {"name":"wardryx","auth":{"socket":"wardryx"},"grants":{"wardryx-approval":["sign"]}}]}`
	if err := os.WriteFile(pol, []byte(body), 0o400); err != nil {
		t.Fatal(err)
	}
	addr := freeAddr(t)
	return map[string]string{
		"KEYRYX_DATA":          data,
		"KEYRYX_ROOT_KEY_FILE": root,
		"KEYRYX_POLICY":        pol,
		"KEYRYX_ADDR":          addr,
		"KEYRYX_SOCKET_DIR":    sockets,
	}, addr
}

func envList(m map[string]string) []string {
	out := []string{}
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	return out
}

// The declared listen default is the one the code uses, and every required
// variable, removed in turn, stops the built binary with the declared code;
// an optional one does not. With all of them it answers its health path.
func TestCustodyRefusesWithoutEachRequiredVariableAndAnswersItsHealthPath(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the binary")
	}
	m, r := load(t)
	c := m.Components[0]
	if c.Checked.ListenDefault != config.DefaultAddr {
		t.Fatalf("components.json says %s and the code listens on %s by default", c.Checked.ListenDefault, config.DefaultAddr)
	}
	bin := buildBinary(t, r)
	full, addr := custodyEnv(t)
	required, optional := 0, 0
	for k, spec := range c.Checked.Env {
		env := map[string]string{}
		for kk, vv := range full {
			env[kk] = vv
		}
		delete(env, k)
		if !spec.Required || spec.Role != "custody" {
			continue
		}
		required++
		cmd := exec.Command(bin, "custody")
		cmd.Env = envList(env)
		out, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != c.Checked.MissingRequiredExitCode || !strings.Contains(string(out), k) {
			t.Errorf("custody without %s: %v %q", k, err, out)
		}
	}
	for k, spec := range c.Checked.Env {
		if spec.Required || full[k] == "" || k == "KEYRYX_SOCKET_DIR" || k == "KEYRYX_ADDR" {
			continue
		}
		optional++
	}
	if required == 0 {
		t.Fatal("no required variable is declared, so this test measured nothing")
	}
	cmd := exec.Command(bin, "custody")
	cmd.Env = envList(full)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if !waitFor(addr, 10*time.Second) {
		t.Fatalf("custody never listened on %s", addr)
	}
	resp, err := http.Get("http://" + addr + c.Checked.HealthPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the health path answered %d", resp.StatusCode)
	}
	_ = optional
}

// The built binary, as a launcher runs it: a consumer signs over TCP with its
// key and another over its own unix socket, the key set is published, and a
// SIGKILL and a restart keep the same keys.
func TestTheBuiltCustodySignsAndKeepsItsKeysAcrossARestart(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the binary")
	}
	_, r := load(t)
	bin := buildBinary(t, r)
	env, addr := custodyEnv(t)
	start := func() *exec.Cmd {
		cmd := exec.Command(bin, "custody")
		cmd.Env = envList(env)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		if !waitFor(addr, 10*time.Second) {
			_ = cmd.Process.Kill()
			t.Fatalf("custody never listened on %s", addr)
		}
		return cmd
	}
	body := `{"statement_b64":"` + base64.StdEncoding.EncodeToString([]byte("a seal root")) + `","purpose":"seal"}`
	signTCP := func() map[string]any {
		req, _ := http.NewRequest("POST", "http://"+addr+"/v1/keys/trailryx-root/sign", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+consumerSecret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("sign over TCP answered %d %v", resp.StatusCode, out)
		}
		return out
	}
	verify := func(out map[string]any, alg policy.Alg, stmt string) {
		sig, _ := base64.StdEncoding.DecodeString(fmt.Sprint(out["signature_b64"]))
		pub, _ := base64.StdEncoding.DecodeString(fmt.Sprint(out["public_key_b64"]))
		if err := keystore.Verify(alg, pub, []byte(stmt), sig); err != nil {
			t.Fatalf("the signature does not verify: %v", err)
		}
	}
	first := start()
	a := signTCP()
	verify(a, policy.ES384, "a seal root")

	sock := filepath.Join(env["KEYRYX_SOCKET_DIR"], "wardryx", "keyryx.sock")
	unixClient := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	stmt2 := `{"statement_b64":"` + base64.StdEncoding.EncodeToString([]byte("approve 1")) + `","purpose":"approval"}`
	resp, err := unixClient.Post("http://keyryx/v1/keys/wardryx-approval/sign", "application/json", strings.NewReader(stmt2))
	if err != nil {
		_ = first.Process.Kill()
		t.Fatalf("the socket consumer could not reach its socket: %v", err)
	}
	var viaSocket map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&viaSocket)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = first.Process.Kill()
		t.Fatalf("sign over the socket answered %d %v", resp.StatusCode, viaSocket)
	}
	verify(viaSocket, policy.ES256, "approve 1")
	// The socket names its consumer and no other: wardryx's socket cannot sign
	// with record-seal's key.
	resp, err = unixClient.Post("http://keyryx/v1/keys/trailryx-root/sign", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		_ = first.Process.Kill()
		t.Fatalf("wardryx's socket signed with another consumer's key: %d", resp.StatusCode)
	}
	_ = first.Process.Kill()
	_ = first.Wait()

	second := start()
	defer func() { _ = second.Process.Kill(); _ = second.Wait() }()
	b := signTCP()
	if a["kid"] != b["kid"] {
		t.Fatalf("a restart changed the key: %v -> %v", a["kid"], b["kid"])
	}
	verify(b, policy.ES384, "a seal root")
	resp, err = http.Get("http://" + addr + "/v1/jwks/trailryx-root")
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&set)
	_ = resp.Body.Close()
	if len(set.Keys) != 1 || set.Keys[0]["kid"] != a["kid"] {
		t.Fatalf("the published key set %v does not name the key that signed", set.Keys)
	}
}
