//go:build linux

package platform

import (
	"fmt"
	"os"
)

const (
	systemdUnitName = "riftroute.service"
	systemdUnitPath = "/etc/systemd/system/riftroute.service"
	installedBin    = "/usr/local/bin/riftrouted"
)

type systemdManager struct{}

func newServiceManager() ServiceManager { return systemdManager{} }

func (systemdManager) Status() ServiceStatus {
	st := ServiceStatus{Manager: "systemd", Label: systemdUnitName}
	st.Installed = fileExists(systemdUnitPath)
	st.Loaded = cmdContains("active (running)", "systemctl", "status", systemdUnitName)
	return st
}

func (systemdManager) Install(daemonBin, socket string, allowUID int) error {
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	if err := copyFile(daemonBin, installedBin, 0o755); err != nil {
		return fmt.Errorf("install binary: %w", err)
	}
	if err := secureRootFile(installedBin, 0o755); err != nil {
		return fmt.Errorf("secure binary: %w", err)
	}
	if err := os.WriteFile(systemdUnitPath, []byte(renderUnit(installedBin, socket, allowUID)), 0o644); err != nil {
		return fmt.Errorf("write unit: %w", err)
	}
	if err := secureRootFile(systemdUnitPath, 0o644); err != nil {
		return fmt.Errorf("secure unit: %w", err)
	}
	if err := runCmd("systemctl", "daemon-reload"); err != nil {
		return err
	}
	return runCmd("systemctl", "enable", "--now", systemdUnitName)
}

func (systemdManager) Uninstall() error {
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	_ = runCmd("systemctl", "disable", "--now", systemdUnitName)
	_ = os.Remove(systemdUnitPath)
	_ = os.Remove(installedBin) // remove the privileged binary too
	_ = runCmd("systemctl", "daemon-reload")
	return nil
}

func (systemdManager) Restart() error {
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	return runCmd("systemctl", "restart", systemdUnitName)
}

func (systemdManager) Start() error {
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	return runCmd("systemctl", "start", systemdUnitName)
}

func (systemdManager) Stop() error {
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	return runCmd("systemctl", "stop", systemdUnitName)
}

func renderUnit(bin, socket string, allowUID int) string {
	allowArg := ""
	if allowUID >= 0 {
		allowArg = fmt.Sprintf(" -allow-uid %d", allowUID)
	}
	return fmt.Sprintf(`[Unit]
Description=RiftRoute split-tunneling routing daemon
After=network.target

[Service]
Type=simple
ExecStart=%s -provider auto -socket %s%s
Restart=on-failure
RestartSec=2
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
`, bin, socket, allowArg)
}
