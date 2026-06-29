//go:build darwin

package platform

import (
	"fmt"
	"os"
)

const (
	launchdLabel = "com.riftroute.daemon"
	launchdPlist = "/Library/LaunchDaemons/com.riftroute.daemon.plist"
	installedBin = "/usr/local/bin/riftrouted"
)

type launchdManager struct{}

func newServiceManager() ServiceManager { return launchdManager{} }

func (launchdManager) Status() ServiceStatus {
	st := ServiceStatus{Manager: "launchd", Label: launchdLabel}
	st.Installed = fileExists(launchdPlist)
	st.Loaded = cmdContains(launchdLabel, "launchctl", "list")
	return st
}

func (launchdManager) Install(daemonBin, socket string, allowUID int) error {
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	if err := copyFile(daemonBin, installedBin, 0o755); err != nil {
		return fmt.Errorf("install binary: %w", err)
	}
	if err := os.MkdirAll("/var/log/riftroute", 0o755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}
	if err := os.WriteFile(launchdPlist, []byte(renderPlist(installedBin, socket, allowUID)), 0o644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}
	// Reload cleanly if already loaded.
	_ = runCmd("launchctl", "unload", launchdPlist)
	return runCmd("launchctl", "load", "-w", launchdPlist)
}

func (launchdManager) Uninstall() error {
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	_ = runCmd("launchctl", "unload", "-w", launchdPlist)
	_ = os.Remove(launchdPlist)
	return nil
}

func (launchdManager) Restart() error {
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	_ = runCmd("launchctl", "unload", launchdPlist)
	return runCmd("launchctl", "load", launchdPlist)
}

func (launchdManager) Start() error {
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	if !fileExists(launchdPlist) {
		return fmt.Errorf("service not installed")
	}
	return runCmd("launchctl", "load", "-w", launchdPlist)
}

func (launchdManager) Stop() error {
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	return runCmd("launchctl", "unload", launchdPlist)
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
