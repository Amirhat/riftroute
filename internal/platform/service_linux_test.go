//go:build linux

package platform

import (
	"path/filepath"
	"testing"
)

// No openvpn ships for Linux (the distribution's package is used), so an
// openvpn lying next to the daemon is never installed.
func TestLinuxShipsNoOpenVPN(t *testing.T) {
	if got := InstalledOpenVPNPath(); got != "" {
		t.Fatalf("InstalledOpenVPNPath = %q", got)
	}
	if got := Helpers(); len(got) != 0 {
		t.Fatalf("Helpers = %+v (Linux uses the distribution's openvpn and strongSwan)", got)
	}
	dir := t.TempDir()
	writeExe(t, filepath.Join(dir, "riftrouted"), "daemon")
	writeExe(t, filepath.Join(dir, "openvpn"), "openvpn")
	if got := BundledOpenVPN(filepath.Join(dir, "riftrouted")); got != "" {
		t.Fatalf("BundledOpenVPN = %q", got)
	}
}
