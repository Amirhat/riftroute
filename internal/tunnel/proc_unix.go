//go:build !windows

package tunnel

import (
	"os/exec"
	"syscall"
)

// ownProcessGroup puts openvpn in its own process group: a Ctrl-C aimed at a
// dev daemon must reach the daemon, which then shuts openvpn down cleanly
// over the management socket.
func ownProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func terminate(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) }

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }
