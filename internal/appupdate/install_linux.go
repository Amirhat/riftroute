//go:build linux

package appupdate

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// AppImageInstaller replaces the running AppImage file with the release's.
type AppImageInstaller struct{}

// NewInstaller returns this system's installer. Only an AppImage updates
// itself; a packaged app (.deb) is updated by the package manager.
func NewInstaller() Installer {
	if os.Getenv("APPIMAGE") == "" {
		return nil
	}
	return AppImageInstaller{}
}

func (AppImageInstaller) Kind() string { return "app-appimage" }

func (AppImageInstaller) Arch() string { return runtime.GOARCH }

// Target is the AppImage file the app runs from.
func Target(string) string { return os.Getenv("APPIMAGE") }

// Check says why this user can't replace the AppImage, or "".
func (AppImageInstaller) Check(target string) string {
	fi, err := os.Lstat(target)
	switch {
	case err != nil:
		return "can't find the AppImage: " + err.Error()
	case !fi.Mode().IsRegular():
		return "the AppImage isn't a plain file"
	case unix.Access(filepath.Dir(target), unix.W_OK) != nil:
		return "the AppImage is in a folder this user can't change; update it the way it was installed"
	}
	return ""
}

// Install copies the verified AppImage beside target and swaps them, keeping
// the previous one as .RiftRoute.AppImage.prev.
func (AppImageInstaller) Install(_ context.Context, artifact, target, version string) error {
	dir := filepath.Dir(target)
	next := filepath.Join(dir, ".RiftRoute-"+version+".AppImage.new")
	if err := copyExecutable(artifact, next); err != nil {
		_ = os.Remove(next)
		return err
	}
	return swap(next, target, filepath.Join(dir, ".RiftRoute.AppImage.prev"))
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// Relaunch runs target once this process has exited.
func (AppImageInstaller) Relaunch(target string) error {
	cmd := exec.Command("/bin/sh", "-c", `while kill -0 "$1" 2>/dev/null; do sleep 0.2; done; exec "$0"`,
		target, strconv.Itoa(os.Getpid()))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // outlives us
	return cmd.Start()
}
