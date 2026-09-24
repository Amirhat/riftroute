//go:build !windows

package tunnel

import (
	"os"
	"os/exec"
	"os/user"
	"strconv"
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

// unprivileged makes a root daemon run cmd as "nobody": for probing a binary
// (openvpn --version) that root doesn't need to trust yet. As any other user
// it's a no-op.
func unprivileged(cmd *exec.Cmd) {
	if os.Geteuid() != 0 {
		return
	}
	uid, gid := uint32(65534), uint32(65534) // Linux's nobody
	if u, err := user.Lookup("nobody"); err == nil {
		// macOS's nobody is -2: parse as signed and keep the bit pattern.
		if v, err := strconv.ParseInt(u.Uid, 10, 64); err == nil {
			uid = uint32(v)
		}
		if v, err := strconv.ParseInt(u.Gid, 10, 64); err == nil {
			gid = uint32(v)
		}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
}
