package platform

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeExe(t *testing.T, p string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// The openvpn that ships with a build sits next to its riftrouted: in the
// release tarball, in the app bundle's Resources/bin, and — behind a bin/
// symlink — in a package manager's libexec.
func TestOpenVPNNextToTheDaemon(t *testing.T) {
	dir := t.TempDir()

	flat := filepath.Join(dir, "flat")
	writeExe(t, filepath.Join(flat, "riftrouted"), "daemon")
	if got := helperNextTo(filepath.Join(flat, "riftrouted"), "openvpn"); got != "" {
		t.Fatalf("a build without openvpn: got %q", got)
	}
	writeExe(t, filepath.Join(flat, "openvpn"), "openvpn")
	if got := helperNextTo(filepath.Join(flat, "riftrouted"), "openvpn"); got != filepath.Join(flat, "openvpn") {
		t.Fatalf("beside the daemon: got %q", got)
	}

	libexec := filepath.Join(dir, "Cellar", "libexec")
	writeExe(t, filepath.Join(libexec, "riftrouted"), "daemon")
	writeExe(t, filepath.Join(libexec, "openvpn"), "openvpn")
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(libexec, "riftrouted"), filepath.Join(bin, "riftrouted")); err != nil {
		t.Fatal(err)
	}
	got := helperNextTo(filepath.Join(bin, "riftrouted"), "openvpn")
	if real, _ := filepath.EvalSymlinks(filepath.Join(libexec, "openvpn")); got == "" || !sameFile(got, real) {
		t.Fatalf("beside the symlinked daemon's target: got %q", got)
	}

	odd := filepath.Join(dir, "odd")
	writeExe(t, filepath.Join(odd, "riftrouted"), "daemon")
	if err := os.MkdirAll(filepath.Join(odd, "openvpn"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := helperNextTo(filepath.Join(odd, "riftrouted"), "openvpn"); got != "" {
		t.Fatalf("a directory named openvpn isn't a program: got %q", got)
	}
	if got := helperNextTo("", "openvpn"); got != "" {
		t.Fatalf("no daemon: got %q", got)
	}
}

func TestInstallOpenVPNCopiesThenSecures(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "bundle", "openvpn")
	writeExe(t, src, "the shipped openvpn")
	dst := filepath.Join(dir, "PrivilegedHelperTools", "riftroute-openvpn")
	writeExe(t, dst, "an older copy")

	var secured []string
	secure := func(p string, mode os.FileMode) error {
		if mode != 0o755 {
			t.Errorf("secured with mode %v", mode)
		}
		secured = append(secured, p)
		return nil
	}
	if err := installHelper("openvpn", src, dst, secure); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); !bytes.Equal(b, []byte("the shipped openvpn")) {
		t.Fatalf("installed %q", b)
	}
	if fi, _ := os.Stat(dst); fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if len(secured) != 1 || secured[0] != dst {
		t.Fatalf("secured %v", secured)
	}
	if _, err := os.Stat(dst + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temporary copy left behind")
	}

	// A file that can't be made root's is an install failure, not a warning.
	refuse := func(string, os.FileMode) error { return errors.New("is a symlink; refusing") }
	if err := installHelper("openvpn", src, dst, refuse); err == nil {
		t.Fatal("an openvpn that couldn't be secured was installed silently")
	}
}

// Each helper a platform ships is found next to the daemon by its own name.
func TestHelpersNextToTheDaemon(t *testing.T) {
	dir := t.TempDir()
	writeExe(t, filepath.Join(dir, "riftrouted"), "daemon")
	writeExe(t, filepath.Join(dir, "charon-cmd"), "charon-cmd")
	h := Helper{Name: "charon-cmd", Installed: "/Library/PrivilegedHelperTools/riftroute-charon-cmd"}
	if got := h.Bundled(filepath.Join(dir, "riftrouted")); got != filepath.Join(dir, "charon-cmd") {
		t.Fatalf("charon-cmd: got %q", got)
	}
	if got := (Helper{Name: "openvpn"}).Bundled(filepath.Join(dir, "riftrouted")); got != "" {
		t.Fatalf("no openvpn in this build: got %q", got)
	}
}
