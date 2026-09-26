//go:build darwin

package appupdate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTargetIsTheBundleTheAppRunsFrom(t *testing.T) {
	for exe, want := range map[string]string{
		"/Applications/RiftRoute.app/Contents/MacOS/RiftRoute":          "/Applications/RiftRoute.app",
		"/Users/me/Applications/RiftRoute.app/Contents/MacOS/RiftRoute": "/Users/me/Applications/RiftRoute.app",
		"/usr/local/bin/riftroute":                                      "", // not in a bundle
		"/tmp/build/bin/RiftRoute":                                      "",
	} {
		if got := Target(exe); got != want {
			t.Errorf("Target(%q) = %q, want %q", exe, got, want)
		}
	}
}

func TestCheckRefusesWhatThisUserCantReplace(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "RiftRoute.app")
	_ = os.MkdirAll(app, 0o755)
	if why := (MacInstaller{}).Check(app); why != "" {
		t.Fatalf("a writable bundle: %q", why)
	}
	if why := (MacInstaller{}).Check("/private/var/folders/x/AppTranslocation/y/d/RiftRoute.app"); why == "" {
		t.Fatal("a translocated copy passed")
	}
	if os.Geteuid() != 0 { // root may write anywhere
		_ = os.Chmod(dir, 0o555)
		defer os.Chmod(dir, 0o755)
		if why := (MacInstaller{}).Check(app); why == "" {
			t.Fatal("a bundle in a read-only folder passed")
		}
	}
	if why := (MacInstaller{}).Check(filepath.Join(dir, "missing.app")); why == "" {
		t.Fatal("a missing bundle passed")
	}
}
