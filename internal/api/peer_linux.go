//go:build linux

package api

import (
	"net"
	"syscall"
)

// PeerUID is the uid of the process at the other end of a unix socket, as the
// kernel recorded it when that process connected (SO_PEERCRED). Nothing the
// peer sends can change it. Anything that is not a unix connection, or whose
// credentials cannot be read, has no uid, and the admin routes refuse it.
func PeerUID(c net.Conn) (int, bool) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credErr != nil || cred == nil {
		return 0, false
	}
	return int(cred.Uid), true
}
