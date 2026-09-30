package updater

// The openvpn that ships with RiftRoute on macOS is updated with the daemon
// and rolled back with it.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeOpenVPN stands in for a shipped openvpn: it prints a version line;
// tag tells builds apart.
func fakeOpenVPN(tag string) []byte {
	return []byte("#!/bin/sh\n# " + tag + "\necho 'OpenVPN 2.6.23 aarch64-apple-darwin [SSL (OpenSSL)] [LZO] [LZ4]'\n")
}

type tarFile struct {
	name string
	body []byte
	typ  byte // tar.TypeReg when 0
}

func releaseTarball(t *testing.T, files ...tarFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		h := &tar.Header{Name: f.name, Mode: 0o755, Size: int64(len(f.body)), Typeflag: f.typ}
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag == tar.TypeSymlink {
			h.Size, h.Linkname = 0, "/opt/homebrew/sbin/openvpn"
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			_, _ = tw.Write(f.body)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// macRelease is a darwin tarball as `make dist` builds it: the CLI, the
// daemon, openvpn and its licenses.
func macRelease(t *testing.T, version string, openvpn []byte) []byte {
	files := []tarFile{{name: "riftroute", body: []byte("#!/bin/sh\n")}, {name: "riftrouted", body: fakeDaemon(version)}}
	if openvpn != nil {
		files = append(files, tarFile{name: "openvpn", body: openvpn},
			tarFile{name: "licenses/openvpn/COPYING", body: []byte("GPLv2")})
	}
	return releaseTarball(t, files...)
}

// withOpenVPN gives the harness an installed openvpn beside the daemon (nil:
// the path is set, but nothing is installed there yet).
func withOpenVPN(t *testing.T, h *harness, installed []byte) string {
	t.Helper()
	p := filepath.Join(filepath.Dir(h.env.Binary), "riftroute-openvpn")
	h.env.OpenVPN, h.u.env.OpenVPN = p, p
	if installed != nil {
		if err := os.WriteFile(p, installed, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func fileIs(t *testing.T, p string, want []byte) bool {
	t.Helper()
	b, err := os.ReadFile(p)
	return err == nil && bytes.Equal(b, want)
}

// installedWithOpenVPN runs a full install of 0.2.7 (with openvpn "new")
// over 0.2.6 (with openvpn installed, unless old is nil).
func installedWithOpenVPN(t *testing.T, old []byte) (*harness, string) {
	t.Helper()
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	f.tgz = macRelease(t, "0.2.7", fakeOpenVPN("new"))
	h := newHarness(t, f, "0.2.6")
	ovpn := withOpenVPN(t, h, old)
	h.check()
	if h.restarts.Load() != 1 {
		t.Fatalf("setup: not installed: %+v", h.u.Status())
	}
	return h, ovpn
}

func TestUpdateInstallsTheShippedOpenVPNWithTheDaemon(t *testing.T) {
	h, ovpn := installedWithOpenVPN(t, fakeOpenVPN("old"))
	if !fileIs(t, h.env.Binary, fakeDaemon("0.2.7")) || !fileIs(t, ovpn, fakeOpenVPN("new")) {
		t.Fatal("daemon and openvpn not both replaced")
	}
	if !fileIs(t, prevBinary(ovpn), fakeOpenVPN("old")) {
		t.Fatal("previous openvpn not kept")
	}
	if fi, _ := os.Stat(ovpn); fi.Mode().Perm() != 0o755 {
		t.Fatalf("openvpn mode %v", fi.Mode())
	}
	if ps, _ := loadPersisted(h.env.StateDir); ps.OpenVPNSwap != helperReplaced {
		t.Fatalf("swap recorded as %q", ps.OpenVPNSwap)
	}
	if fileExists(stagingDir(h.env.StateDir)) {
		t.Fatal("staging left behind")
	}
}

func TestHealthRollbackRestoresOpenVPN(t *testing.T) {
	h, ovpn := installedWithOpenVPN(t, fakeOpenVPN("old"))
	env := guardEnv(h, "0.2.7")
	for i := 0; i <= maxBoots; i++ { // three failed starts, then the rollback
		_, _ = BootGuard(env)
	}
	if !fileIs(t, h.env.Binary, fakeDaemon("0.2.6")) || !fileIs(t, ovpn, fakeOpenVPN("old")) {
		t.Fatal("daemon and openvpn not both rolled back")
	}
	if fileExists(prevBinary(ovpn)) {
		t.Fatal("openvpn .prev kept after it was restored")
	}
	// Rolling back again (a crash before the daemon's own restore) is harmless.
	restoreHelpersFor(env)
	if !fileIs(t, ovpn, fakeOpenVPN("old")) {
		t.Fatal("a repeated restore changed openvpn")
	}
}

func TestUserRollbackRestoresOpenVPN(t *testing.T) {
	h, ovpn := installedWithOpenVPN(t, fakeOpenVPN("old"))
	g, _ := BootGuard(guardEnv(h, "0.2.7"))
	g.Confirm()
	h.env.Current = "0.2.7"
	u2, _ := New(h.env)
	if err := u2.RequestRollback(); err != nil {
		t.Fatal(err)
	}
	if g, err := BootGuard(guardEnv(h, "0.2.7")); err != nil || !g.RestartNow {
		t.Fatalf("rollback start: %v %+v", err, g)
	}
	if !fileIs(t, h.env.Binary, fakeDaemon("0.2.6")) || !fileIs(t, ovpn, fakeOpenVPN("old")) {
		t.Fatal("daemon and openvpn not both rolled back")
	}
}

// The first release that ships openvpn adds it; rolling that release back
// keeps it. Removing it would leave the previous daemon — which may run
// tunnels too — without one, and every openvpn RiftRoute ships works with
// every daemon (one from before tunnels ignores it).
func TestRollingBackTheFirstShippedOpenVPNKeepsIt(t *testing.T) {
	for _, by := range []string{"health", "you", "a crash before the daemon's rename"} {
		t.Run(by, func(t *testing.T) {
			h, ovpn := installedWithOpenVPN(t, nil)
			if !fileIs(t, ovpn, fakeOpenVPN("new")) || fileExists(prevBinary(ovpn)) {
				t.Fatal("openvpn not added (or a .prev invented)")
			}
			switch by {
			case "health":
				for i := 0; i <= maxBoots; i++ {
					_, _ = BootGuard(guardEnv(h, "0.2.7"))
				}
			case "you":
				g, _ := BootGuard(guardEnv(h, "0.2.7"))
				g.Confirm()
				h.env.Current = "0.2.7"
				u2, _ := New(h.env)
				if err := u2.RequestRollback(); err != nil {
					t.Fatal(err)
				}
				if g, err := BootGuard(guardEnv(h, "0.2.7")); err != nil || !g.RestartNow {
					t.Fatalf("rollback start: %v %+v", err, g)
				}
			default:
				if err := os.WriteFile(h.env.Binary, fakeDaemon("0.2.6"), 0o755); err != nil {
					t.Fatal(err)
				}
				_, _ = BootGuard(guardEnv(h, "0.2.6"))
			}
			if !fileIs(t, h.env.Binary, fakeDaemon("0.2.6")) {
				t.Fatal("daemon not rolled back")
			}
			if !fileIs(t, ovpn, fakeOpenVPN("new")) {
				t.Fatal("the rollback removed the openvpn the update added")
			}
			if ps, _ := loadPersisted(h.env.StateDir); ps.OpenVPNSwap != "" {
				t.Fatalf("swap still recorded as %q", ps.OpenVPNSwap)
			}
		})
	}
}

// A release without openvpn (a fork's build) leaves the installed one alone
// — and a rollback of it too; an older .prev doesn't belong to it and goes.
func TestReleaseWithoutOpenVPNLeavesItAlone(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	f.tgz = macRelease(t, "0.2.7", nil)
	h := newHarness(t, f, "0.2.6")
	ovpn := withOpenVPN(t, h, fakeOpenVPN("current"))
	if err := os.WriteFile(prevBinary(ovpn), fakeOpenVPN("from an earlier update"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.check()
	if h.restarts.Load() != 1 || !fileIs(t, h.env.Binary, fakeDaemon("0.2.7")) {
		t.Fatalf("daemon not installed: %+v", h.u.Status())
	}
	if !fileIs(t, ovpn, fakeOpenVPN("current")) || fileExists(prevBinary(ovpn)) {
		t.Fatal("openvpn touched, or a stale .prev kept")
	}
	for i := 0; i <= maxBoots; i++ {
		_, _ = BootGuard(guardEnv(h, "0.2.7"))
	}
	if !fileIs(t, h.env.Binary, fakeDaemon("0.2.6")) || !fileIs(t, ovpn, fakeOpenVPN("current")) {
		t.Fatal("rolling back a release without openvpn changed openvpn")
	}
}

// Like the daemon, the staged openvpn's hash is checked again just before
// the swap.
func TestStagedOpenVPNIsRecheckedAtTheSwap(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	f.tgz = macRelease(t, "0.2.7", fakeOpenVPN("new"))
	h := newHarness(t, f, "0.2.6")
	ovpn := withOpenVPN(t, h, fakeOpenVPN("old"))
	h.idle.Store(false)
	if st := h.check(); st.Staged != "0.2.7" {
		t.Fatalf("setup: %+v", st)
	}
	staged := filepath.Join(stagingDir(h.env.StateDir), "0.2.7", "openvpn")
	if err := os.WriteFile(staged, []byte("#!/bin/sh\necho swapped in staging\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.idle.Store(true)
	h.tick()
	if h.restarts.Load() != 0 || !fileIs(t, ovpn, fakeOpenVPN("old")) || !fileIs(t, h.env.Binary, fakeDaemon("0.2.6")) {
		t.Fatal("installed a staged openvpn that changed on disk")
	}
	if st := h.u.Status(); !strings.Contains(st.Error, "changed on disk") || st.Staged != "" {
		t.Fatalf("status: %+v", st)
	}
}

// A crash after openvpn was replaced but before the daemon was: the old
// daemon starts, and BootGuard puts the old openvpn back beside it.
func TestCrashBeforeTheDaemonRenameRestoresOpenVPN(t *testing.T) {
	h, ovpn := installedWithOpenVPN(t, fakeOpenVPN("old"))
	// Undo the daemon's rename, as if the crash came just before it.
	if err := os.WriteFile(h.env.Binary, fakeDaemon("0.2.6"), 0o755); err != nil {
		t.Fatal(err)
	}
	if g, err := BootGuard(guardEnv(h, "0.2.6")); err != nil || g.RestartNow {
		t.Fatalf("guard: %v %+v", err, g)
	}
	if !fileIs(t, ovpn, fakeOpenVPN("old")) {
		t.Fatal("the new openvpn was left beside the old daemon")
	}
	if ps, _ := loadPersisted(h.env.StateDir); ps.Skip != "" {
		t.Fatalf("an unfinished swap skipped %s", ps.Skip)
	}
}

// An openvpn in the release that doesn't run here is the release's fault.
func TestReleaseWhoseOpenVPNDoesntRunIsSkipped(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	f.tgz = macRelease(t, "0.2.7", []byte("#!/bin/sh\necho 'dyld: Library not loaded' >&2\nexit 134\n"))
	h := newHarness(t, f, "0.2.6")
	ovpn := withOpenVPN(t, h, fakeOpenVPN("old"))
	st := h.check()
	if st.Staged != "" || !strings.Contains(st.Error, "openvpn --version") || h.restarts.Load() != 0 {
		t.Fatalf("broken openvpn: %+v", st)
	}
	if ps, _ := loadPersisted(h.env.StateDir); ps.Skip != "0.2.7" {
		t.Fatal("a release with a broken openvpn wasn't skipped")
	}
	if !fileIs(t, ovpn, fakeOpenVPN("old")) {
		t.Fatal("openvpn touched")
	}
}

// Where no openvpn ships (Linux), one in a tarball is never extracted.
func TestNoOpenVPNIsTakenWhereNoneShips(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	f.tgz = macRelease(t, "0.2.7", fakeOpenVPN("new"))
	h := newHarness(t, f, "0.2.6") // env.OpenVPN == ""
	h.idle.Store(false)
	if st := h.check(); st.Staged != "0.2.7" {
		t.Fatalf("setup: %+v", st)
	}
	if fileExists(filepath.Join(stagingDir(h.env.StateDir), "0.2.7", "openvpn")) || len(h.u.staged.helpers) != 0 {
		t.Fatal("openvpn staged where none ships")
	}
}

func TestExtractReleaseRefusesOddOpenVPNs(t *testing.T) {
	dir := t.TempDir()
	daemon := tarFile{name: "riftrouted", body: fakeDaemon("0.2.7")}
	extract := func(files ...tarFile) (bool, error) {
		tgz := filepath.Join(dir, "r.tar.gz")
		if err := os.WriteFile(tgz, releaseTarball(t, files...), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := extractRelease(tgz, filepath.Join(dir, "riftrouted"), dir, helpersAt("/x/riftroute-openvpn", ""))
		return got["openvpn"], err
	}
	isBroken := func(err error) bool { var b errBroken; return err != nil && errors.As(err, &b) }

	if ok, err := extract(daemon, tarFile{name: "./openvpn", body: fakeOpenVPN("x")}); !ok || err != nil {
		t.Fatalf("plain: %v %v", ok, err)
	}
	if ok, err := extract(daemon); ok || err != nil {
		t.Fatalf("absent: %v %v", ok, err)
	}
	if _, err := extract(daemon, tarFile{name: "openvpn", typ: tar.TypeSymlink}); !isBroken(err) {
		t.Fatalf("a symlink openvpn: %v", err)
	}
	if _, err := extract(daemon, tarFile{name: "openvpn", typ: tar.TypeDir}); !isBroken(err) {
		t.Fatalf("a directory openvpn: %v", err)
	}
	if _, err := extract(daemon, tarFile{name: "openvpn", body: bytes.Repeat([]byte{0}, maxOpenVPNSize+1)}); !isBroken(err) {
		t.Fatalf("an oversized openvpn: %v", err)
	}
	if _, err := extract(daemon, tarFile{name: "openvpn", body: fakeOpenVPN("a")}, tarFile{name: "openvpn", body: fakeOpenVPN("b")}); !isBroken(err) {
		t.Fatalf("two openvpns: %v", err)
	}
	if _, err := extract(tarFile{name: "openvpn", body: fakeOpenVPN("x")}); !isBroken(err) {
		t.Fatalf("no daemon: %v", err)
	}
}
