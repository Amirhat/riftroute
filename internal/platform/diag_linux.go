//go:build linux

package platform

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// DaemonLogTail returns the last n lines of the daemon's journal and where
// they came from (needs root or the systemd-journal group; empty otherwise).
func DaemonLogTail(n int) (text, source string) {
	out, err := cmdOutput("journalctl", "-u", systemdUnitName, "-n", strconv.Itoa(n), "--no-pager", "-o", "short-iso")
	if err != nil || strings.TrimSpace(out) == "" {
		return "", ""
	}
	return strings.TrimSpace(out), "journalctl -u " + systemdUnitName
}

// OSDescription is e.g. "Ubuntu 24.04.1 LTS, kernel 6.8.0-45-generic (amd64)".
func OSDescription() string {
	name := "Linux"
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
				name = strings.Trim(v, `"`)
			}
		}
	}
	if k, err := cmdOutput("uname", "-r"); err == nil && strings.TrimSpace(k) != "" {
		name += ", kernel " + strings.TrimSpace(k)
	}
	return name + " (" + runtime.GOARCH + ")"
}

// HostNames lists this machine's names (identifying; reports redact them).
func HostNames() []string {
	var out []string
	if h, err := os.Hostname(); err == nil {
		out = append(out, h)
	}
	return out
}
