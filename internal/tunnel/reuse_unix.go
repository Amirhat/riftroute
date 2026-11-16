//go:build !windows

package tunnel

import "golang.org/x/sys/unix"

// reusePort lets several L2TP tunnels' sockets share local port 1701, each
// connected to its own server.
func reusePort(fd uintptr) error {
	if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return err
	}
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}
