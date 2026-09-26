//go:build darwin

package appupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// MacInstaller replaces a RiftRoute.app bundle with the one in a release's
// DMG.
type MacInstaller struct{}

// NewInstaller returns this system's installer.
func NewInstaller() Installer { return MacInstaller{} }

func (MacInstaller) Kind() string { return "app-dmg" }
func (MacInstaller) Arch() string { return "universal" }

// Target is the bundle the running app is in: exe is .../X.app/Contents/MacOS/X.
func Target(exe string) string {
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	macos := filepath.Dir(exe)
	contents := filepath.Dir(macos)
	bundle := filepath.Dir(contents)
	if filepath.Base(macos) != "MacOS" || filepath.Base(contents) != "Contents" || !strings.HasSuffix(bundle, ".app") {
		return ""
	}
	return bundle
}

// Check says why this user can't replace the bundle, or "".
func (MacInstaller) Check(target string) string {
	if strings.Contains(target, "/AppTranslocation/") {
		return "macOS is running RiftRoute from a temporary copy; move it to Applications"
	}
	fi, err := os.Lstat(target)
	switch {
	case err != nil:
		return "can't find the app: " + err.Error()
	case !fi.IsDir():
		return "the app isn't a bundle"
	}
	// Renaming the bundle needs write access to its folder and — for a
	// directory — to the bundle itself.
	for _, p := range []string{filepath.Dir(target), target} {
		if unix.Access(p, unix.W_OK) != nil {
			return "the app is installed where this user can't change it; install updates the way it was installed"
		}
	}
	return ""
}

// Install mounts the DMG read-only, checks the app in it (this app's bundle
// identifier, the release's version, an intact signature), copies it beside
// target and swaps them, keeping the previous app as .RiftRoute.app.prev.
func (MacInstaller) Install(ctx context.Context, dmg, target, version string) error {
	mnt, err := os.MkdirTemp("", "rr-app-update-")
	if err != nil {
		return err
	}
	defer os.Remove(mnt)
	if out, err := run(ctx, "/usr/bin/hdiutil", "attach", "-nobrowse", "-readonly", "-noautoopen", "-noverify", "-mountpoint", mnt, dmg); err != nil {
		return fmt.Errorf("open the disk image: %w: %s", err, out)
	}
	defer func() {
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if _, err := run(dctx, "/usr/bin/hdiutil", "detach", mnt); err != nil {
			_, _ = run(dctx, "/usr/bin/hdiutil", "detach", "-force", mnt)
		}
	}()
	src := filepath.Join(mnt, "RiftRoute.app")
	if err := checkBundle(ctx, src, target, version); err != nil {
		return err
	}
	next := filepath.Join(filepath.Dir(target), ".RiftRoute-"+version+".app.new")
	_ = os.RemoveAll(next)
	if out, err := run(ctx, "/usr/bin/ditto", src, next); err != nil {
		_ = os.RemoveAll(next)
		return fmt.Errorf("copy the new app: %w: %s", err, out)
	}
	return swap(next, target, filepath.Join(filepath.Dir(target), ".RiftRoute.app.prev"))
}

// checkBundle makes sure src is this app, at the release's version, and
// intact.
func checkBundle(ctx context.Context, src, target, version string) error {
	want, err := bundleID(ctx, target)
	if err != nil {
		return fmt.Errorf("read this app's identifier: %w", err)
	}
	if got, err := bundleID(ctx, src); err != nil || got != want {
		return fmt.Errorf("the disk image's app isn't RiftRoute (%q, want %q)", got, want)
	}
	out, err := run(ctx, filepath.Join(src, "Contents/Resources/bin/riftrouted"), "-version")
	if f := strings.Fields(out); err != nil || len(f) == 0 || strings.TrimPrefix(f[0], "v") != version {
		return fmt.Errorf("the disk image's app isn't version %s (%q)", version, strings.TrimSpace(out))
	}
	if out, err := run(ctx, "/usr/bin/codesign", "--verify", "--deep", "--strict", src); err != nil {
		return fmt.Errorf("the new app's signature doesn't verify: %w: %s", err, out)
	}
	return nil
}

func bundleID(ctx context.Context, bundle string) (string, error) {
	out, err := run(ctx, "/usr/bin/plutil", "-extract", "CFBundleIdentifier", "raw", "-o", "-", filepath.Join(bundle, "Contents/Info.plist"))
	return strings.TrimSpace(out), err
}

// Relaunch opens target once this process has exited (a second instance
// would only hand focus to this one and quit).
func (MacInstaller) Relaunch(target string) error {
	cmd := exec.Command("/bin/sh", "-c", `while kill -0 "$1" 2>/dev/null; do sleep 0.2; done; exec /usr/bin/open "$0"`,
		target, strconv.Itoa(os.Getpid()))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // outlives us
	return cmd.Start()
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if ctx.Err() != nil && err != nil {
		err = errors.Join(err, ctx.Err())
	}
	return string(out), err
}
