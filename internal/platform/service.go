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
	Install(daemonBin, socket string) error
	Uninstall() error
	Restart() error
	Status() ServiceStatus
}

// NewServiceManager returns the per-OS service manager.
func NewServiceManager() ServiceManager { return newServiceManager() }

// FindDaemonBinary locates the riftrouted binary: next to the running CLI, then
// on PATH.
func FindDaemonBinary() (string, error) {
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), "riftrouted")
		if fileExists(cand) {
			return cand, nil
		}
	}
	if p, err := exec.LookPath("riftrouted"); err == nil {
		return p, nil
	}
	return "", errors.New("riftrouted binary not found (build it, or place it on PATH)")
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
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
