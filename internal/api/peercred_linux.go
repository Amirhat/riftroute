//go:build linux

package api

import "golang.org/x/sys/unix"

// peerCred reads the connecting peer's uid/gid on Linux via SO_PEERCRED.
func peerCred(fd uintptr) (uint32, uint32, error) {
	uc, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, 0, err
	}
	return uc.Uid, uc.Gid, nil
}
