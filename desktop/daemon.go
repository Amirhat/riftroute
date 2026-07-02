package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Amirhat/riftroute/internal/apiclient"
	"github.com/Amirhat/riftroute/internal/platform"
)

// DaemonInfo is the GUI's view of the system service + live connection, so the
// setup screen can decide what to offer (install / start / stop / restart).
type DaemonInfo struct {
	Manager   string `json:"manager"` // launchd | systemd | unsupported
	Installed bool   `json:"installed"`
	Loaded    bool   `json:"loaded"`
	Reachable bool   `json:"reachable"`
	Version   string `json:"version,omitempty"`
	CanManage bool   `json:"can_manage"` // false where service install isn't supported
}

// GetDaemonInfo reports whether riftrouted is installed, loaded, and answering.
func (a *App) GetDaemonInfo() DaemonInfo {
	st := platform.NewServiceManager().Status()
	ctx, cancel := context.WithTimeout(a.ctx, 2*time.Second)
	defer cancel()
	ver, perr := a.client.Ping(ctx)
	return DaemonInfo{
		Manager:   st.Manager,
		Installed: st.Installed,
		Loaded:    st.Loaded,
		Reachable: perr == nil,
		Version:   ver,
		CanManage: st.Manager == "launchd" || st.Manager == "systemd",
	}
}

// InstallDaemon installs + starts riftrouted as a system service, prompting for
// admin privileges via the OS. The daemon is authorized for this desktop user so
// the (unprivileged) GUI can control it afterward.
func (a *App) InstallDaemon() error {
	return a.privilegedDaemon("install", fmt.Sprintf("--allow-uid %d", os.Getuid()))
}
func (a *App) StartDaemon() error     { return a.privilegedDaemon("start", "") }
func (a *App) StopDaemon() error      { return a.privilegedDaemon("stop", "") }
func (a *App) RestartDaemon() error   { return a.privilegedDaemon("restart", "") }
func (a *App) UninstallDaemon() error { return a.privilegedDaemon("uninstall", "") }

// privilegedDaemon runs `riftroute daemon <sub> [args]` as root via the native
// admin prompt, then nudges the UI to re-check the connection.
func (a *App) privilegedDaemon(sub, extra string) error {
	cli, err := platform.FindCLIBinary()
	if err != nil {
		return fmt.Errorf("couldn't locate the riftroute CLI: %w", err)
	}
	if err := runElevated(cli, sub, extra); err != nil {
		return err
	}
	// After install the daemon listens on the SYSTEM socket, not the per-user dev
	// socket the GUI first bound to — re-resolve and reconnect, else the UI would
	// stay "offline" even on a perfect install.
	a.reconnect()
	time.Sleep(600 * time.Millisecond)
	a.emit("rr:connection", map[string]any{"reachable": a.Reachable()})
	return nil
}

// reconnect re-resolves the daemon socket (it changes from the per-user dev
// socket to the system socket once the service is installed) and restarts the
// live event stream against it, so the UI comes online after an install.
func (a *App) reconnect() {
	if a.cancelEvents != nil {
		a.cancelEvents()
	}
	a.client = apiclient.New(platform.ClientSocket())
	ec, cancel := context.WithCancel(a.ctx)
	a.cancelEvents = cancel
	go a.streamEvents(ec)
}

// runElevated executes `<cli> daemon <sub> [extra]` with administrator
// privileges, showing the OS's native password prompt.
func runElevated(cli, sub, extra string) error {
	if runtime.GOOS == "linux" {
		if _, err := exec.LookPath("pkexec"); err != nil {
			return fmt.Errorf("no graphical privilege helper (pkexec) found — run in a terminal: sudo %s daemon %s %s", cli, sub, strings.TrimSpace(extra))
		}
	}
	name, args, err := elevateCmd(runtime.GOOS, cli, sub, extra)
	if err != nil {
		return err
	}
	return runOnce(name, args...)
}

// elevateCmd builds the privileged command that runs `<cli> daemon <sub> [extra]`
// behind an OS admin prompt. Pure (no exec) so it is unit-testable: macOS uses
// AppleScript's "with administrator privileges"; Linux uses pkexec.
func elevateCmd(goos, cli, sub, extra string) (string, []string, error) {
	switch goos {
	case "darwin":
		// Strip the download-quarantine from the bundled CLIs FIRST (as root, inside
		// the elevated shell) so Gatekeeper doesn't block executing them — otherwise
		// an app opened via right-click→Open (which only clears the main binary)
		// would fail the install silently. /bin/sh + xattr aren't quarantined, so the
		// strip runs before we exec the now-clean CLI.
		inner := fmt.Sprintf("/usr/bin/xattr -dr com.apple.quarantine %q 2>/dev/null; %q daemon %s",
			filepath.Dir(cli), cli, sub)
		if extra != "" {
			inner += " " + extra
		}
		script := fmt.Sprintf("do shell script %q with administrator privileges", inner)
		return "osascript", []string{"-e", script}, nil
	case "linux":
		args := []string{cli, "daemon", sub}
		if extra != "" {
			args = append(args, strings.Fields(extra)...)
		}
		return "pkexec", args, nil
	default:
		return "", nil, fmt.Errorf("daemon management isn't supported on %s", goos)
	}
}

func runOnce(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		s := strings.TrimSpace(string(out))
		// User dismissed the macOS auth dialog.
		if strings.Contains(s, "-128") || strings.Contains(s, "User canceled") {
			return fmt.Errorf("cancelled")
		}
		if s == "" {
			s = err.Error()
		}
		return fmt.Errorf("%s", s)
	}
	return nil
}
