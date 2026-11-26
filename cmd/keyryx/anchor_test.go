package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/statement"
	"github.com/TAIPANBOX/keyryx/internal/tsa"
	"github.com/TAIPANBOX/keyryx/internal/wlog"
)

// A head's root is read back from lowercase hex and nothing else, and the
// time-stamp asked for covers exactly the latest head's signed input.

func TestAHeadRootIsLowercaseHexOfASHA384Digest(t *testing.T) {
	for in, want := range map[string]string{"": "", "00": "00", "0a": "0a", "ff10": "ff10", "9f": "9f"} {
		got, err := hexDecode(in)
		if err != nil || hex.EncodeToString(got) != want {
			t.Errorf("hexDecode(%q) = %x, %v", in, got, err)
		}
	}
	for _, in := range []string{"0", "abc", "0A", "FF", "g0", "0g", "/0", ":0", "`0", "0 "} {
		if got, err := hexDecode(in); err == nil {
			t.Errorf("hexDecode(%q) took it as %x", in, got)
		}
	}
	root := strings.Repeat("ab", 48)
	r, err := rootOf(wlog.Head{Root: root})
	if err != nil || hex.EncodeToString(r[:]) != root {
		t.Fatalf("a SHA-384 root: %x %v", r, err)
	}
	for _, bad := range []string{"", strings.Repeat("ab", 47), strings.Repeat("ab", 49), strings.Repeat("AB", 48), strings.Repeat("zz", 48)} {
		if _, err := rootOf(wlog.Head{Root: bad}); err == nil || !strings.Contains(err.Error(), "SHA-384") {
			t.Errorf("root %q: %v", bad, err)
		}
	}
}

func signedLog(t *testing.T) *wlog.Log {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "w")
	_ = os.Mkdir(dir, 0o700)
	now := func() time.Time { return t0 }
	store, err := keystore.Open(dir, [32]byte{7, 7}, wlog.Keys, now)
	if err != nil {
		t.Fatal(err)
	}
	l, err := wlog.Open(dir, statement.StoreKeys(store, wlog.KeyES384, wlog.KeyMLDSA), now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if err := l.Append(wlog.Entry{Kind: "stream", SeenAt: t0.Unix(), Stream: "wardryx.ndjson", Lines: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Sign(store); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestAnAnchorNeedsAHeadAndStampsExactlyTheLatestOne(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "empty")
	_ = os.Mkdir(dir, 0o700)
	store, err := keystore.Open(dir, [32]byte{6}, wlog.Keys, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	empty, err := wlog.Open(dir, statement.StoreKeys(store, wlog.KeyES384, wlog.KeyMLDSA), func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	asked := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { asked = true }))
	defer srv.Close()
	if err := anchor(context.Background(), empty, &tsa.Client{URL: srv.URL, HTTP: srv.Client()}); err == nil || !strings.Contains(err.Error(), "no tree head") {
		t.Fatalf("a log with no head: %v", err)
	}
	if asked {
		t.Fatal("a log with no head asked the TSA anyway")
	}

	l := signedLog(t)
	h, _ := l.Latest()
	root, _ := rootOf(h)
	want := sha512.Sum384(wlog.HeadInput(h.Size, root, h.At))
	var mu sync.Mutex
	var body []byte
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		body = b
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer refusing.Close()
	before := len(l.Entries())
	err = anchor(context.Background(), l, &tsa.Client{URL: refusing.URL, HTTP: refusing.Client()})
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("a TSA that refused: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !bytes.Contains(body, want[:]) {
		t.Fatalf("the query does not carry the SHA-384 of the latest head's input")
	}
	if len(l.Entries()) != before {
		t.Fatal("a refused time-stamp was written into the log")
	}
}

// A socket a previous run left behind is replaced; anything else at the path
// is never removed.
func TestListenSocketReplacesAStaleSocketAndNothingElse(t *testing.T) {
	dir := shortDir(t)
	path := filepath.Join(dir, "s.sock")
	old, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	old.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = old.Close()
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("no stale socket to replace: %v", err)
	}
	l, err := listenSocket(path, 0o640)
	if err != nil {
		t.Fatalf("a stale socket was not replaced: %v", err)
	}
	defer l.Close()
	if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("the socket's mode: %v %v", info, err)
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("the new socket does not take a connection: %v", err)
	}
	_ = c.Close()

	file := filepath.Join(dir, "f.sock")
	_ = os.WriteFile(file, []byte("keep me"), 0o600)
	if _, err := listenSocket(file, 0o600); err == nil || !strings.Contains(err.Error(), "is not a socket") {
		t.Fatalf("a regular file at the path: %v", err)
	}
	if b, _ := os.ReadFile(file); string(b) != "keep me" {
		t.Fatal("a file custody did not make was removed")
	}
	if _, err := listenSocket(filepath.Join(dir, "missing", "s.sock"), 0o600); err == nil {
		t.Fatal("a socket in a directory that is not there was listened on")
	}
}
