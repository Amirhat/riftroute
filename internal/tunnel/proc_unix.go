//go:build !windows

package tunnel

import (
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

// ownProcessGroup puts openvpn in its own process group: a Ctrl-C aimed at a
// dev daemon must reach the daemon, which then shuts openvpn down cleanly
// over the management socket. On Linux openvpn also gets SIGTERM if the
// daemon dies (see parentDeath).
func ownProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	parentDeath(cmd.SysProcAttr)
}

func terminate(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) }

func forceKill(pid int) error { return syscall.Kill(pid, syscall.SIGKILL) }

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

// ownedByUs reports whether a file belongs to the effective user.
func ownedByUs(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

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
