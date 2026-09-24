//go:build darwin

package platform

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const launchdTarget = "system/" + launchdLabel

// launchctl runs one launchctl verb; printService returns `launchctl print`
// output for our job (error when it isn't loaded). Package vars so the
// sequencing below is testable without touching launchd.
var (
	launchctl    = func(args ...string) error { return runCmd("launchctl", args...) }
	printService = func() (string, error) { return cmdOutput("launchctl", "print", launchdTarget) }
	now          = time.Now
	sleep        = time.Sleep
)

// unloadTimeout bounds the wait for bootout to finish: launchd sends SIGTERM,
// then SIGKILL after the job's exit timeout (20s by default).
const unloadTimeout = 25 * time.Second

// startTimeout bounds how long start/restart/install wait for the daemon to
// accept connections. It exceeds launchd's 10s respawn throttle, so a throttled
// (not failed) start is waited out rather than reported as a failure.
const startTimeout = 15 * time.Second

// bootService (re)loads the daemon into the SYSTEM launchd domain and starts it.
// Uses the modern verbs — `launchctl load` is legacy and does not reliably load
// a system LaunchDaemon on macOS 11+ (it was the reason the service "installed
// but never started"). Falls back to `load -w` only on ancient macOS.
//
// `bootout` returns before the job is actually gone. Bootstrapping straight
// after it races the teardown: bootstrap fails ("5: Input/output error") or
// the OLD definition stays loaded — and with it the old process, still
// serving the socket after an "install" (Clew lesson). So wait until launchd
// no longer knows the job, then bootstrap, retrying briefly.
func bootService() error {
	if err := unbootService(); err != nil {
		return err
	}
	_ = launchctl("enable", launchdTarget) // undo any earlier disable
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			sleep(time.Duration(attempt) * 500 * time.Millisecond)
		}
		if err = launchctl("bootstrap", "system", launchdPlist); err == nil {
			break
		}
	}
	if err != nil {
		if lerr := launchctl("load", "-w", launchdPlist); lerr != nil {
			return fmt.Errorf("launchctl bootstrap failed: %w", err)
		}
	}
	// RunAtLoad already started it; kickstart WITHOUT -k is a no-op then and
	// only starts a job that didn't (-k would kill the fresh process).
	_ = launchctl("kickstart", launchdTarget)
	return nil
}

// unbootService removes the job from launchd and waits until it's really gone.
func unbootService() error {
	_ = launchctl("bootout", "system", launchdPlist)
	_ = launchctl("bootout", launchdTarget) // belt-and-suspenders (plist may be gone)
	deadline := now().Add(unloadTimeout)
	for {
		if _, err := printService(); err != nil {
			return nil // launchd no longer knows the job
		}
		if now().After(deadline) {
			return fmt.Errorf("launchd did not unload %s within %s; the old daemon may still be running", launchdLabel, unloadTimeout)
		}
		sleep(200 * time.Millisecond)
	}
}

// waitForSocket blocks until the new daemon ACCEPTS a connection on its socket
// (the file alone proves nothing — a crashed predecessor can leave it behind),
// or returns an error with the daemon's log tail so the failure is visible
// instead of a silent "installed but not running".
func waitForSocket(socket string) error {
	if err := dialUntil(socket, startTimeout); err != nil {
		return fmt.Errorf("riftrouted did not come up within %s — recent log (%s/riftrouted.err.log):\n%s",
			startTimeout, logDir, readTail(logDir+"/riftrouted.err.log", 1200))
	}
	return nil
}

// dialUntil polls until something accepts on the unix socket or timeout
// passes. It dials rather than stat()ing: a socket file left by a killed
// daemon exists but refuses connections.
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

// startService makes sure the job is running without disturbing a healthy
// one: a loaded job only gets a kickstart (a reload would kill it — the old
// "Start never brings it back" loop); an unloaded one is bootstrapped.
func startService() error {
	if _, err := printService(); err == nil {
		_ = launchctl("kickstart", launchdTarget)
		return nil
	}
	return bootService()
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
	// `launchctl print system/…` works unprivileged; `launchctl list` only
	// shows the caller's own domain, so it reported a running system daemon
	// as not loaded to every non-root user.
	if out, err := printService(); err == nil {
		st.Loaded = true
		st.Detail = launchdState(out)
	}
	return st
}

// launchdState extracts the job state ("running", "waiting", …) from
// `launchctl print` output.
func launchdState(out string) string {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " = ")
		if ok && k == "state" {
			return strings.TrimSpace(v)
		}
	}
	return ""
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
	if err := unbootService(); err != nil {
		return err // don't delete the binary out from under a live daemon
	}
	_ = os.Remove(launchdPlist)
	_ = os.Remove(installedBin) // remove the privileged binary too
	return nil
}

func (launchdManager) Restart() error {
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	if err := bootService(); err != nil { // unloads (and waits) first
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
	if err := startService(); err != nil {
		return err
	}
	return waitForSocket(systemSocket)
}

func (launchdManager) Stop() error {
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	return unbootService()
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
