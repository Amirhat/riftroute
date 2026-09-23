//go:build darwin

package platform

import (
	"os"
	"runtime"
	"strings"
)

// DaemonLogTail returns the last n lines of the installed daemon's log (slog
// writes to stderr, which launchd sends to riftrouted.err.log) and where they
// came from. Empty when the daemon runs in a terminal (dev) instead.
func DaemonLogTail(n int) (text, source string) {
	for _, p := range []string{logDir + "/riftrouted.err.log", logDir + "/riftrouted.log"} {
		if t := tailLines(p, n); t != "" {
			return t, p
		}
	}
	return "", ""
}

// OSDescription is e.g. "macOS 15.6 (arm64)".
func OSDescription() string {
	v, err := cmdOutput("sw_vers", "-productVersion")
	if err != nil || strings.TrimSpace(v) == "" {
		return "macOS (" + runtime.GOARCH + ")"
	}
	return "macOS " + strings.TrimSpace(v) + " (" + runtime.GOARCH + ")"
}

// HostNames lists this machine's names (they are identifying, so reports
// redact them): the hostname plus the macOS computer and local host names.
func HostNames() []string {
	var out []string
	if h, err := os.Hostname(); err == nil {
		out = append(out, h, strings.TrimSuffix(h, ".local"))
	}
	for _, key := range []string{"ComputerName", "LocalHostName"} {
		if v, err := cmdOutput("scutil", "--get", key); err == nil {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return out
}
