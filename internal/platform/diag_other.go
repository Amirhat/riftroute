//go:build !darwin && !linux

package platform

import (
	"os"
	"runtime"
)

// DaemonLogTail is unavailable where the daemon can't be installed.
func DaemonLogTail(int) (string, string) { return "", "" }

// OSDescription is the bare platform.
func OSDescription() string { return runtime.GOOS + " (" + runtime.GOARCH + ")" }

// HostNames lists this machine's names (identifying; reports redact them).
func HostNames() []string {
	if h, err := os.Hostname(); err == nil {
		return []string{h}
	}
	return nil
}
