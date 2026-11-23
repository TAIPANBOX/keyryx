//go:build !linux

package api

import (
	"context"
	"net"
	"testing"
)

func TestThePeersUIDIsTheKernelsWord(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, ok := PeerUID(a); ok {
		t.Fatal("a platform that cannot read peer credentials gave a uid")
	}
	if _, ok := AdminConnContext(context.Background(), a).Value(peerKey{}).(int); ok {
		t.Fatal("the admin listener gave a uid to a connection with no peer credentials")
	}
}
