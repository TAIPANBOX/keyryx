package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/wlog"
)

// Both roles are driven through run, as the binary is: they come up on a
// complete environment, serve, say what they found wrong at the start, and
// stop cleanly on SIGTERM. Each refuses the start, naming the variable, when
// a part of its data or address does not take it (CLAUDE.md invariant 6).

// syncBuf is a writer the role's goroutines and the test share.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	_ = l.Close()
	return a
}

func writeMode(t *testing.T, path, body string, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

var plainClient = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}

// startRole runs a role in the background, waits until url answers (the
// role's listeners serve only after its signal handler is in place), and
// returns a stop that sends SIGTERM and reads the exit code.
func startRole(t *testing.T, role, url string) func() (int, string) {
	t.Helper()
	stop, _ := startRoleLogged(t, role, url)
	return stop
}

// startRoleLogged is startRole that also hands back what the role writes on
// stderr while it runs.
func startRoleLogged(t *testing.T, role, url string) (func() (int, string), *syncBuf) {
	t.Helper()
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	errBuf := &syncBuf{}
	done := make(chan int, 1)
	go func() { done <- run([]string{role}, io.Discard, errBuf) }()
	deadline := time.Now().Add(20 * time.Second)
	for {
		select {
		case code := <-done:
			t.Fatalf("%s exited %d before it served: %s", role, code, errBuf.String())
		default:
		}
		if resp, err := plainClient.Get(url); err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never answered on %s: %s", role, url, errBuf.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	return func() (int, string) {
		t.Helper()
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case code := <-done:
			return code, errBuf.String()
		case <-time.After(20 * time.Second):
			t.Fatalf("%s did not stop on SIGTERM: %s", role, errBuf.String())
		}
		return -1, ""
	}, errBuf
}

const socketPolicy = `{"version":1,"keys":[{"name":"wardryx-approval","alg":"ES256"}],
 "consumers":[{"name":"wardryx","auth":{"socket":"wardryx"},"grants":{"wardryx-approval":["sign"]}}]}`

type custodyPaths struct {
	data, sockets, events, statements, addr string
}

// custodyEnv sets a complete custody environment with one socket consumer
// and a statements directory, and returns where everything is.
func custodyEnv(t *testing.T) custodyPaths {
	t.Helper()
	dir := shortDir(t)
	p := custodyPaths{data: filepath.Join(dir, "data"), sockets: filepath.Join(dir, "sock"), events: filepath.Join(dir, "events"),
		statements: filepath.Join(dir, "pub"), addr: freeAddr(t)}
	if err := os.Mkdir(p.data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(p.sockets, "wardryx"), 0o750); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(p.sockets, 0o750)
	_ = os.Chmod(filepath.Join(p.sockets, "wardryx"), 0o770)
	for _, d := range []string{p.events, p.statements} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(d, 0o755)
	}
	env := map[string]string{
		"KEYRYX_DATA":           p.data,
		"KEYRYX_ROOT_KEY_FILE":  writeMode(t, filepath.Join(dir, "root.key"), strings.Repeat("ab", 32)+"\n", 0o400),
		"KEYRYX_POLICY":         writeMode(t, filepath.Join(dir, "policy.json"), socketPolicy, 0o400),
		"KEYRYX_SOCKET_DIR":     p.sockets,
		"KEYRYX_EVENTS":         filepath.Join(p.events, "keyryx-custody.ndjson"),
		"KEYRYX_STATEMENTS_DIR": p.statements,
		"KEYRYX_ADDR":           p.addr,
		"KEYRYX_ADMIN_KEYS":     "",
		"KEYRYX_K8S_ISSUERS":    "",
		"KEYRYX_PUBLISH_AHEAD":  "",
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	return p
}

func socketGet(t *testing.T, sock, path string) (int, string) {
	t.Helper()
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}}}
	resp, err := c.Get("http://keyryx" + path)
	if err != nil {
		t.Fatalf("%s: %v", sock, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// tamperMAC rewrites the state MAC of every record file under dir, so the
// files still open under the root key but their state is not custody's own.
func tamperMAC(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil || m["mac"] == nil {
			return nil
		}
		m["mac"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		b, _ := json.Marshal(m)
		n++
		return os.WriteFile(path, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestCustodyComesUpServesItsSocketsAndStopsOnSIGTERM(t *testing.T) {
	p := custodyEnv(t)
	stop := startRole(t, "custody", "http://"+p.addr+"/healthz")

	admin := filepath.Join(p.data, "admin.sock")
	consumer := filepath.Join(p.sockets, "wardryx", SocketName)
	for path, want := range map[string]os.FileMode{admin: 0o600, consumer: 0o666} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != want {
			t.Fatalf("%s: %v, mode %v, want a socket with %o", path, err, info, want)
		}
	}
	if code, body := socketGet(t, consumer, "/healthz"); code != http.StatusOK || !strings.Contains(body, "ok") {
		t.Fatalf("the consumer's socket: %d %s", code, body)
	}
	// The public copy of the delegation root is written before custody serves.
	raw, err := os.ReadFile(filepath.Join(p.statements, "delegation-root.jwks.json"))
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err != nil || json.Unmarshal(raw, &set) != nil || len(set.Keys) < 2 {
		t.Fatalf("the exported root key set: %v %s", err, raw)
	}
	// The admin command reaches this custody on its socket, as its own user:
	// served on Linux, where the kernel reports the peer's uid, and refused
	// with its status alone everywhere else (invariant 43).
	code, out, errOut := call("admin", "rotate", "wardryx-approval")
	if runtime.GOOS == "linux" {
		if code != 0 || !strings.Contains(out, "kid") {
			t.Fatalf("admin rotate against a running custody: exit %d, %q %q", code, out, errOut)
		}
	} else if code != 1 || out != "" || !strings.Contains(errOut, "403") {
		t.Fatalf("admin rotate without peer credentials: exit %d, %q %q", code, out, errOut)
	}
	code, errOut = stop()
	if code != 0 {
		t.Fatalf("custody stopped on SIGTERM with %d: %s", code, errOut)
	}
	if !strings.Contains(errOut, "keyryx custody dev: listening on "+p.addr+", 1 consumer sockets") {
		t.Fatalf("the start line: %s", errOut)
	}
	if strings.Contains(errOut, "ALARM") {
		t.Fatalf("an honest data directory raised an alarm: %s", errOut)
	}

	// A key state custody did not write is said at the next start, on stderr
	// and on the use log, and custody still comes up.
	if n := tamperMAC(t, filepath.Join(p.data, "keys")); n == 0 {
		t.Fatal("no key record to tamper with")
	}
	stop = startRole(t, "custody", "http://"+p.addr+"/healthz")
	code, errOut = stop()
	if code != 0 || !strings.Contains(errOut, "ALARM: the key wardryx-approval") || !strings.Contains(errOut, "state_mac_mismatch") {
		t.Fatalf("a tampered key state: exit %d, stderr %s", code, errOut)
	}
	use, _ := os.ReadFile(filepath.Join(p.data, "use.ndjson"))
	if !strings.Contains(string(use), `"op":"state_alarm"`) {
		t.Fatalf("the use log does not carry the alarm: %s", use)
	}
}

func TestCustodyRefusesTheStartWhenAPartOfItsStateDoesNotTakeIt(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(t *testing.T, p custodyPaths)
		want   []string
	}{
		"the event stream's directory is gone": {func(t *testing.T, p custodyPaths) { _ = os.RemoveAll(p.events) },
			[]string{"KEYRYX_EVENTS", "its directory is not there"}},
		"the key directory is a file": {func(t *testing.T, p custodyPaths) { writeMode(t, filepath.Join(p.data, "keys"), "x", 0o600) },
			[]string{"KEYRYX_DATA", "keys"}},
		"the statement directory is a file": {func(t *testing.T, p custodyPaths) { writeMode(t, filepath.Join(p.data, "statements"), "x", 0o600) },
			[]string{"KEYRYX_DATA", "statements"}},
		"the use log is a directory": {func(t *testing.T, p custodyPaths) { _ = os.Mkdir(filepath.Join(p.data, "use.ndjson"), 0o700) },
			[]string{"KEYRYX_DATA", "use.ndjson"}},
		"the outbox is a directory": {func(t *testing.T, p custodyPaths) { _ = os.Mkdir(filepath.Join(p.data, "announce.ndjson"), 0o700) },
			[]string{"KEYRYX_DATA", "announce"}},
		"the statements directory holds a stranger's file": {func(t *testing.T, p custodyPaths) { writeMode(t, filepath.Join(p.statements, "notes.txt"), "x", 0o644) },
			[]string{"KEYRYX_STATEMENTS_DIR", "notes.txt"}},
		"the admin socket's path is a file": {func(t *testing.T, p custodyPaths) { writeMode(t, filepath.Join(p.data, "admin.sock"), "x", 0o600) },
			[]string{"KEYRYX_DATA: the admin socket", "is not a socket"}},
		"a consumer's socket path is a file": {func(t *testing.T, p custodyPaths) {
			writeMode(t, filepath.Join(p.sockets, "wardryx", SocketName), "x", 0o600)
		}, []string{"KEYRYX_SOCKET_DIR: consumer wardryx", "is not a socket"}},
	} {
		t.Run(name, func(t *testing.T) {
			p := custodyEnv(t)
			tc.mutate(t, p)
			code, out, errOut := call("custody")
			if code != exitRefused || out != "" || !strings.Contains(errOut, "refusing to start") {
				t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
			}
			for _, w := range tc.want {
				if !strings.Contains(errOut, w) {
					t.Errorf("the refusal does not say %q: %s", w, errOut)
				}
			}
			// Whatever it opened before refusing, it let go of: the address
			// is free again.
			l, err := net.Listen("tcp", p.addr)
			if err != nil {
				t.Fatalf("custody refused and still holds %s: %v", p.addr, err)
			}
			_ = l.Close()
		})
	}
}

func TestCustodyRefusesAnAddressAlreadyTaken(t *testing.T) {
	p := custodyEnv(t)
	l, err := net.Listen("tcp", p.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	code, _, errOut := call("custody")
	if code != exitRefused || !strings.Contains(errOut, "KEYRYX_ADDR") {
		t.Fatalf("a taken address: exit %d, %s", code, errOut)
	}
}

type witnessPaths struct {
	data, events, addr string
}

func witnessEnv(t *testing.T) witnessPaths {
	t.Helper()
	dir := shortDir(t)
	p := witnessPaths{data: filepath.Join(dir, "wdata"), events: filepath.Join(dir, "events"), addr: freeAddr(t)}
	if err := os.Mkdir(p.data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p.events, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"KEYRYX_DATA", "KEYRYX_ROOT_KEY_FILE", "KEYRYX_WITNESS_CHECKPOINTS", "KEYRYX_WITNESS_STREAM_KEYS",
		"KEYRYX_WITNESS_DELEGATION_ROOT_PIN", "KEYRYX_WITNESS_ALERTS", "KEYRYX_WITNESS_RECORDS", "KEYRYX_WITNESS_FULL_BYTES",
		"KEYRYX_WITNESS_FULL_INTERVAL", "KEYRYX_WITNESS_SEAL_EVERY", "KEYRYX_WITNESS_SEAL_LINES", "KEYRYX_WITNESS_NAME",
		"KEYRYX_WITNESS_TSA_URL", "KEYRYX_WITNESS_TSA_CA", "KEYRYX_WITNESS_TSA_EVERY", "KEYRYX_WITNESS_CUSTODY_URL"} {
		t.Setenv(k, "")
	}
	t.Setenv("KEYRYX_WITNESS_DATA", p.data)
	t.Setenv("KEYRYX_WITNESS_ROOT_KEY_FILE", writeMode(t, filepath.Join(dir, "witness.key"), strings.Repeat("cd", 32)+"\n", 0o400))
	t.Setenv("KEYRYX_WITNESS_EVENTS", p.events)
	t.Setenv("KEYRYX_WITNESS_ADDR", p.addr)
	t.Setenv("KEYRYX_WITNESS_INTERVAL", "1s")
	return p
}

func TestTheWitnessComesUpSignsAHeadTriesItsTSAAndStopsOnSIGTERM(t *testing.T) {
	p := witnessEnv(t)
	// A TSA the witness reaches over TLS it does not trust: the time-stamp is
	// not taken, the witness says so and goes on.
	tsaSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer tsaSrv.Close()
	ca := writeMode(t, filepath.Join(t.TempDir(), "tsa-ca.pem"),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tsaSrv.Certificate().Raw})), 0o600)
	t.Setenv("KEYRYX_WITNESS_TSA_URL", tsaSrv.URL)
	t.Setenv("KEYRYX_WITNESS_TSA_CA", ca)
	t.Setenv("KEYRYX_WITNESS_CUSTODY_URL", "http://127.0.0.1:1")
	tsaSrv.Config.ErrorLog = log.New(io.Discard, "", 0)
	tsaSrv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}

	stop, running := startRoleLogged(t, "witness", "http://"+p.addr+"/healthz")
	var head struct {
		Size int64  `json:"size"`
		Root string `json:"root"`
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := plainClient.Get("http://" + p.addr + "/v1/witness/head")
		if err == nil {
			ok := resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&head) == nil
			_ = resp.Body.Close()
			if ok {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the witness never signed a head")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(head.Root) != 96 {
		t.Fatalf("the head's root is not a SHA-384 digest: %+v", head)
	}
	for !strings.Contains(running.String(), "the time-stamp was not taken") {
		if time.Now().After(deadline) {
			t.Fatalf("the witness never reported the time-stamp: %s", running.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	code, errOut := stop()
	if code != 0 {
		t.Fatalf("the witness stopped on SIGTERM with %d: %s", code, errOut)
	}
	if !strings.Contains(errOut, "keyryx witness dev: listening on "+p.addr) {
		t.Fatalf("the start line: %s", errOut)
	}
	if !strings.Contains(errOut, "the time-stamp was not taken") || !strings.Contains(errOut, "certificate") {
		t.Fatalf("an untrusted TSA was not reported as a failed time-stamp: %s", errOut)
	}
	if strings.Contains(errOut, "ALARM") {
		t.Fatalf("an honest witness directory raised an alarm: %s", errOut)
	}

	// A witness key whose state the witness did not write is said at the
	// next start.
	if n := tamperMAC(t, filepath.Join(p.data, "keys")); n == 0 {
		t.Fatal("no witness key record to tamper with")
	}
	t.Setenv("KEYRYX_WITNESS_TSA_URL", "")
	stop = startRole(t, "witness", "http://"+p.addr+"/healthz")
	code, errOut = stop()
	if code != 0 || !strings.Contains(errOut, "ALARM: the witness key") || !strings.Contains(errOut, "state_mac_mismatch") {
		t.Fatalf("a tampered witness key: exit %d, %s", code, errOut)
	}
}

func TestTheWitnessRefusesTheStartWhenAPartOfItsStateDoesNotTakeIt(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(t *testing.T, p witnessPaths)
		want   []string
	}{
		"the key directory is a file": {func(t *testing.T, p witnessPaths) { writeMode(t, filepath.Join(p.data, "keys"), "x", 0o600) },
			[]string{"KEYRYX_WITNESS_DATA", "keys"}},
		"the log is a directory": {func(t *testing.T, p witnessPaths) { _ = os.Mkdir(filepath.Join(p.data, wlog.LogFile), 0o700) },
			[]string{"KEYRYX_WITNESS_DATA", "the witness log"}},
		"the alert stream's directory is not there": {func(t *testing.T, p witnessPaths) {
			t.Setenv("KEYRYX_WITNESS_ALERTS", filepath.Join(p.events, "gone", "keyryx.ndjson"))
		}, []string{"KEYRYX_WITNESS_ALERTS"}},
		"the address is taken": {func(t *testing.T, p witnessPaths) {
			l, err := net.Listen("tcp", p.addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = l.Close() })
		}, []string{"KEYRYX_WITNESS_ADDR"}},
	} {
		t.Run(name, func(t *testing.T) {
			p := witnessEnv(t)
			tc.mutate(t, p)
			code, out, errOut := call("witness")
			if code != exitRefused || out != "" || !strings.Contains(errOut, "refusing to start") {
				t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
			}
			for _, w := range tc.want {
				if !strings.Contains(errOut, w) {
					t.Errorf("the refusal does not say %q: %s", w, errOut)
				}
			}
		})
	}
}
