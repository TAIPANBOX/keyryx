//go:build !linux

package api

import "net"

// PeerUID cannot read a peer's credentials on this platform with the standard
// library, so no peer has a uid and every admin request is refused. The
// published images are Linux only.
func PeerUID(net.Conn) (int, bool) { return 0, false }
