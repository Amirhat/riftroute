package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/platform"
)

// daemon install says whether tunnels' openvpn comes with it (macOS only).
func TestDaemonInstallReportsTheShippedOpenVPN(t *testing.T) {
	dir := t.TempDir()
	daemon := filepath.Join(dir, "riftrouted")
	if err := os.WriteFile(daemon, []byte("daemon"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errw bytes.Buffer
	reportOpenVPN(&out, &errw, daemon)
	if platform.InstalledOpenVPNPath() == "" { // Linux: the distribution's openvpn
		if out.Len()+errw.Len() != 0 {
			t.Fatalf("nothing to say where none ships: %q %q", out.String(), errw.String())
		}
		return
	}
	if !strings.Contains(errw.String(), "doesn't include openvpn") || out.Len() != 0 {
		t.Fatalf("without openvpn: %q %q", out.String(), errw.String())
	}
	if _, err := os.Stat(platform.InstalledOpenVPNPath()); err != nil && !strings.Contains(errw.String(), "riftroute update check") {
		t.Fatalf("without openvpn, and none installed: say how to get it: %q", errw.String())
	}
	if err := os.WriteFile(filepath.Join(dir, "openvpn"), []byte("openvpn"), 0o755); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errw.Reset()
	reportOpenVPN(&out, &errw, daemon)
	if !strings.Contains(out.String(), "installing openvpn for tunnels") || !strings.Contains(out.String(), platform.InstalledOpenVPNPath()) ||
		errw.Len() != 0 {
		t.Fatalf("with openvpn: %q %q", out.String(), errw.String())
	}
}
