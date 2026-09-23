//go:build darwin

package platform

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"
)

const launchdTarget = "system/" + launchdLabel

// startTimeout bounds how long start/restart/install wait for the daemon to
// accept connections. It exceeds launchd's 10s respawn throttle, so a throttled
// (not failed) start is waited out rather than reported as a failure.
const startTimeout = 15 * time.Second

// bootService (re)loads the daemon into the SYSTEM launchd domain and starts it,
// replacing any loaded copy so a changed plist/binary takes effect.
func bootService() error {
	_ = runCmd("launchctl", "bootout", "system", launchdPlist) // clear any prior copy
	return loadService()
}

// loadService bootstraps the plist into the system domain; RunAtLoad starts it.
// Uses the modern verbs — `launchctl load` is legacy and does not reliably load
// a system LaunchDaemon on macOS 11+ (it was the reason the service "installed
// but never started"). Falls back to `load -w` only on ancient macOS.
func loadService() error {
	_ = runCmd("launchctl", "enable", launchdTarget) // undo any earlier disable
	if err := runCmd("launchctl", "bootstrap", "system", launchdPlist); err != nil {
		if lerr := runCmd("launchctl", "load", "-w", launchdPlist); lerr != nil {
			return fmt.Errorf("launchctl bootstrap failed: %w", err)
		}
	}
	// Ensure it's running now — WITHOUT -k: bootstrap already launched it, and
	// killing that fresh instance makes launchd throttle the respawn for its 10s
	// minimum runtime, so the daemon wasn't up yet when start returned.
	_ = runCmd("launchctl", "kickstart", launchdTarget)
	return nil
}

func unbootService() {
	_ = runCmd("launchctl", "bootout", "system", launchdPlist)
	_ = runCmd("launchctl", "bootout", launchdTarget) // belt-and-suspenders
}

// serviceLoaded reports whether the job is loaded in the system domain. Uses
// `launchctl print` (works unprivileged) — `launchctl list` only shows the
// caller's own domain, so run as the desktop user it never saw the daemon.
func serviceLoaded() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "launchctl", "print", launchdTarget).Run() == nil
}

// waitForSocket blocks until the daemon accepts a connection on its socket
// (proof it actually came up), or returns an error with the daemon's log tail so
// the failure is visible instead of a silent "installed but not running".
func waitForSocket(socket string) error {
	if err := dialUntil(socket, startTimeout); err != nil {
		return fmt.Errorf("riftrouted did not come up within %s — recent log (%s/riftrouted.err.log):\n%s",
			startTimeout, logDir, readTail(logDir+"/riftrouted.err.log", 1200))
	}
	return nil
}

// dialUntil polls until something accepts on the unix socket or timeout passes.
// It dials rather than stat()ing: a socket file left by a killed daemon exists
// but refuses connections.
func dialUntil(socket string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		c, err := net.DialTimeout("unix", socket, 250*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(250 * time.Millisecond)
	}
}

const (
	launchdLabel = "com.riftroute.daemon"
	launchdPlist = "/Library/LaunchDaemons/com.riftroute.daemon.plist"
	// Root-only, non-SIP location for the privileged binary. Deliberately NOT
	// /usr/local/bin: on macOS that is frequently owned/writable by the admin user
	// (Homebrew), which would let a non-root user swap a binary launchd runs as
	// root (LPE). /Library/PrivilegedHelperTools is root:wheel.
	installDir   = "/Library/PrivilegedHelperTools"
	installedBin = installDir + "/riftrouted"
	logDir       = "/var/log/riftroute"
)

type launchdManager struct{}

func newServiceManager() ServiceManager { return launchdManager{} }

func (launchdManager) Status() ServiceStatus {
	st := ServiceStatus{Manager: "launchd", Label: launchdLabel}
	st.Installed = fileExists(launchdPlist)
	st.Loaded = serviceLoaded()
	return st
}

func (launchdManager) Install(daemonBin, socket string, allowUID int) error {
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	// Install the root-run binary into a root-only directory (LPE defense).
	if err := secureRootDir(installDir); err != nil {
		return fmt.Errorf("secure install dir: %w", err)
	}
	if err := copyFile(daemonBin, installedBin, 0o755); err != nil {
		return fmt.Errorf("install binary: %w", err)
	}
	if err := secureRootFile(installedBin, 0o755); err != nil {
		return fmt.Errorf("secure binary: %w", err)
	}
	// Harden the log dir; reject a pre-planted symlink (arbitrary-root-write).
	if err := secureRootDir(logDir); err != nil {
		return fmt.Errorf("secure log dir: %w", err)
	}
	if err := os.WriteFile(launchdPlist, []byte(renderPlist(installedBin, socket, allowUID)), 0o644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}
	if err := secureRootFile(launchdPlist, 0o644); err != nil {
		return fmt.Errorf("secure plist: %w", err)
	}
	if err := bootService(); err != nil {
		return err
	}
	return waitForSocket(socket) // confirm it actually started, else surface the log
}

func (launchdManager) Uninstall() error {
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	unbootService()
	_ = os.Remove(launchdPlist)
	_ = os.Remove(installedBin) // remove the privileged binary too
	return nil
}

func (launchdManager) Restart() error {
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	unbootService()
	if err := loadService(); err != nil {
		return err
	}
	return waitForSocket(systemSocket)
}

func (launchdManager) Start() error {
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	if !fileExists(launchdPlist) {
		return fmt.Errorf("service not installed")
	}
	if serviceLoaded() {
		// Already loaded (the caller may just have lost track of it): make sure
		// it runs, but never kill a healthy instance the way a reload would.
		_ = runCmd("launchctl", "kickstart", launchdTarget)
	} else if err := loadService(); err != nil {
		return err
	}
	return waitForSocket(systemSocket)
}

func (launchdManager) Stop() error {
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	unbootService()
	return nil
}

func renderPlist(bin, socket string, allowUID int) string {
	allowArg := ""
	if allowUID >= 0 {
		allowArg = fmt.Sprintf("\n    <string>-allow-uid</string>\n    <string>%d</string>", allowUID)
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>-provider</string>
    <string>auto</string>
    <string>-socket</string>
    <string>%s</string>%s
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/riftroute/riftrouted.log</string>
  <key>StandardErrorPath</key><string>/var/log/riftroute/riftrouted.err.log</string>
</dict>
</plist>
`, launchdLabel, bin, socket, allowArg)
}
