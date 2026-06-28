//go:build darwin

package api

import "golang.org/x/sys/unix"

// peerCred reads the connecting peer's uid/gid on macOS via LOCAL_PEERCRED
// (getsockopt SOL_LOCAL). This is the macOS analogue of SO_PEERCRED.
func peerCred(fd uintptr) (uint32, uint32, error) {
	xu, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, 0, err
	}
	var gid uint32
	if xu.Ngroups > 0 {
		gid = xu.Groups[0]
	}
	return xu.Uid, gid, nil
}
