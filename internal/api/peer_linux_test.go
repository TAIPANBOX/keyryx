//go:build linux

package api

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestThePeersUIDIsTheKernelsWord(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "kx")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	l, err := net.Listen("unix", filepath.Join(dir, "admin.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := net.Dial("unix", filepath.Join(dir, "admin.sock"))
		if err == nil {
			defer c.Close()
			_, _ = c.Read(make([]byte, 1))
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	uid, ok := PeerUID(c)
	if !ok || uid != os.Getuid() {
		t.Fatalf("the peer's uid: %d %v, want %d", uid, ok, os.Getuid())
	}
	if got, ok := AdminConnContext(context.Background(), c).Value(peerKey{}).(int); !ok || got != os.Getuid() {
		t.Fatalf("the admin listener's context carries %d %v, want %d", got, ok, os.Getuid())
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, ok := PeerUID(a); ok {
		t.Fatal("a connection that is not a unix socket has a uid")
	}
	if _, ok := AdminConnContext(context.Background(), a).Value(peerKey{}).(int); ok {
		t.Fatal("the admin listener gave a uid to a connection with no peer credentials")
	}
}
