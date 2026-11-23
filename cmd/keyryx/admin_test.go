package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheAdminCommandRefusesWhatItCannotSend(t *testing.T) {
	t.Setenv("KEYRYX_DATA", "/tmp/kx-none")
	for name, args := range map[string][]string{
		"nothing":            {"admin"},
		"an unknown verb":    {"admin", "delete", "wardryx-approval"},
		"no name":            {"admin", "rotate"},
		"two names":          {"admin", "rotate", "a", "b"},
		"a path in the name": {"admin", "rotate", "../keys"},
		"a query in the kid": {"admin", "revoke", "abc?x=1"},
		"a slash in the kid": {"admin", "revoke", "a/b"},
		"an empty name":      {"admin", "rotate", ""},
	} {
		if code, out, _ := call(args...); code != exitRefused || out != "" {
			t.Errorf("%s: exit %d, stdout %q", name, code, out)
		}
	}
	t.Setenv("KEYRYX_DATA", "")
	if code, _, errOut := call("admin", "rotate", "wardryx-approval"); code != exitRefused || !strings.Contains(errOut, "KEYRYX_DATA") {
		t.Errorf("no data directory: exit %d, %q", code, errOut)
	}
	dir := shortDir(t)
	t.Setenv("KEYRYX_DATA", dir)
	if code, _, errOut := call("admin", "rotate", "wardryx-approval"); code != 1 || !strings.Contains(errOut, "admin.sock") {
		t.Errorf("no custody on the socket: exit %d, %q", code, errOut)
	}
}

// The command sends exactly the route it names to the socket in the data
// directory, prints the answer on success, and only the status on a refusal.
func TestTheAdminCommandAsksCustodyOnTheSocketInItsDataDirectory(t *testing.T) {
	dir := shortDir(t)
	t.Setenv("KEYRYX_DATA", dir)
	l, err := net.Listen("unix", filepath.Join(dir, "admin.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.Path)
		if strings.Contains(r.URL.Path, "refuse-me") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":"Forbidden","secret_reason":"admin_peer_refused"}`)
			return
		}
		_, _ = io.WriteString(w, `{"kid":"new"}`)
	})}
	go func() { _ = srv.Serve(l) }()
	defer srv.Shutdown(context.Background())

	if code, out, _ := call("admin", "rotate", "keyryx.delegation-root"); code != 0 || out != `{"kid":"new"}` {
		t.Fatalf("rotate: exit %d, %q", code, out)
	}
	if code, _, _ := call("admin", "revoke", "FXG0i91Nag8j0ITnQFhO8mLmW8ijBkZvamjNsS9g1dE"); code != 0 {
		t.Fatalf("revoke: exit %d", code)
	}
	code, out, errOut := call("admin", "revoke", "refuse-me")
	if code != 1 || out != "" || !strings.Contains(errOut, "403") || strings.Contains(errOut, "admin_peer") {
		t.Fatalf("a refusal: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	want := []string{"POST /v1/keys/keyryx.delegation-root/rotate", "POST /v1/kids/FXG0i91Nag8j0ITnQFhO8mLmW8ijBkZvamjNsS9g1dE/revoke", "POST /v1/kids/refuse-me/revoke"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("custody was asked %v, want %v", got, want)
	}
}

func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "kx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}
