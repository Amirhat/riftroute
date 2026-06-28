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

func (launchdManager) Install(daemonBin, socket string) error {
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	if err := copyFile(daemonBin, installedBin, 0o755); err != nil {
		return fmt.Errorf("install binary: %w", err)
	}
	if err := os.MkdirAll("/var/log/riftroute", 0o755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}
	if err := os.WriteFile(launchdPlist, []byte(renderPlist(installedBin, socket)), 0o644); err != nil {
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

func renderPlist(bin, socket string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>-socket</string>
    <string>%s</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/riftroute/riftrouted.log</string>
  <key>StandardErrorPath</key><string>/var/log/riftroute/riftrouted.err.log</string>
</dict>
</plist>
`, launchdLabel, bin, socket)
}
