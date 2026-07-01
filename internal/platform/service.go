package platform

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ErrNeedRoot is returned by privileged service operations when not run as root.
var ErrNeedRoot = errors.New("must be run as root (try: sudo riftroute daemon ...)")

// ServiceStatus reports the installed/loaded state of the system service.
type ServiceStatus struct {
	Installed bool   `json:"installed"`
	Loaded    bool   `json:"loaded"`
	Manager   string `json:"manager"` // "launchd" | "systemd" | "unsupported"
	Label     string `json:"label"`
	Detail    string `json:"detail,omitempty"`
}

// ServiceManager installs/controls riftrouted as an OS service (launchd on
// macOS, systemd on Linux). Privileged operations require root; the agent never
// runs these — the user does (spec §12).
type ServiceManager interface {
	// Install copies the daemon, writes the service unit (launching it with
	// -allow-uid so the desktop user can control the root daemon), and starts it.
	Install(daemonBin, socket string, allowUID int) error
	Uninstall() error
	Restart() error
	Start() error // load/start an already-installed service
	Stop() error  // stop a running service without removing it
	Status() ServiceStatus
}

// NewServiceManager returns the per-OS service manager.
func NewServiceManager() ServiceManager { return newServiceManager() }

// FindDaemonBinary locates the riftrouted binary: next to the running CLI, then
// on PATH.
func FindDaemonBinary() (string, error) {
	return findBinary("riftrouted")
}

// FindCLIBinary locates the riftroute CLI binary: next to the running executable
// (e.g. bundled inside RiftRoute.app/Contents/MacOS), then on PATH. The GUI uses
// it to run privileged `riftroute daemon …` commands via an admin prompt.
func FindCLIBinary() (string, error) {
	return findBinary("riftroute")
}

func findBinary(name string) (string, error) {
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for _, cand := range []string{
			// macOS .app bundle FIRST: the GUI is Contents/MacOS/RiftRoute and the
			// CLIs are bundled under Contents/Resources/bin. We must check here before
			// the sibling, because the filesystem is case-insensitive — the sibling
			// "MacOS/riftroute" would otherwise resolve to the GUI binary "RiftRoute".
			filepath.Join(dir, "..", "Resources", "bin", name),
			filepath.Join(dir, name), // sibling (dev ./bin, Linux layout)
		} {
			if fileExists(cand) && !sameFile(cand, exe) {
				return cand, nil
			}
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("%s binary not found (build it, or place it on PATH)", name)
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// secureRootDir creates dir (if absent) and forces it to root-owned, 0755, and
// not a symlink — so a non-root user can't plant or swap what lives there. Called
// as root during install; prevents LPE via an attacker-writable install/log path.
func secureRootDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to install (possible attack)", dir)
	}
	if err := os.Chown(dir, 0, 0); err != nil {
		return err
	}
	return os.Chmod(dir, 0o755)
}

// secureRootFile forces path to root-owned with the given mode and rejects a
// symlink — so a root-run binary/plist can't be replaced by a non-root user.
func secureRootFile(path string, mode os.FileMode) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing (possible attack)", path)
	}
	if err := os.Chown(path, 0, 0); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// sameFile reports whether two paths resolve to the same on-disk file (used to
// avoid handing back the GUI's own executable on case-insensitive filesystems,
// where "riftroute" and "RiftRoute" collide).
func sameFile(a, b string) bool {
	fa, err1 := os.Stat(a)
	fb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(fa, fb)
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// atomic replace
	return os.Rename(tmp, dst)
}

func runCmd(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, string(out))
	}
	return nil
}

func cmdContains(needle string, name string, args ...string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), needle)
}
