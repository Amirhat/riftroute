package updater

// strongSwan's charon-cmd (IKEv2 tunnels) ships beside the daemon on macOS
// like openvpn: updated with it, rolled back with it, and put back from the
// newest release when an older updater left it out.

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeCharonCmd stands in for a shipped charon-cmd: it prints its version
// line; tag tells builds apart.
func fakeCharonCmd(tag string) []byte {
	return []byte("#!/bin/sh\n# " + tag + "\necho 'charon-cmd, strongSwan 6.1.0'\n")
}

// macReleaseWith is a darwin tarball with both helpers (either may be nil).
func macReleaseWith(t *testing.T, version string, openvpn, charon []byte) []byte {
	files := []tarFile{{name: "riftroute", body: []byte("#!/bin/sh\n")}, {name: "riftrouted", body: fakeDaemon(version)}}
	if openvpn != nil {
		files = append(files, tarFile{name: "openvpn", body: openvpn})
	}
	if charon != nil {
		files = append(files, tarFile{name: "charon-cmd", body: charon},
			tarFile{name: "licenses/strongswan/COPYING", body: []byte("GPLv2")})
	}
	return releaseTarball(t, files...)
}

// withCharonCmd gives the harness an installed charon-cmd beside the daemon
// (nil: the path is set, but nothing is installed there yet).
func withCharonCmd(t *testing.T, h *harness, installed []byte) string {
	t.Helper()
	p := filepath.Join(filepath.Dir(h.env.Binary), "riftroute-charon-cmd")
	h.env.CharonCmd, h.u.env.CharonCmd = p, p
	if installed != nil {
		if err := os.WriteFile(p, installed, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// An update replaces both helpers with the daemon, keeping the old ones;
// a failed health check puts all three back.
func TestUpdateAndRollbackCarryBothHelpers(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	f.tgz = macReleaseWith(t, "0.2.7", fakeOpenVPN("new"), fakeCharonCmd("new"))
	h := newHarness(t, f, "0.2.6")
	ovpn := withOpenVPN(t, h, fakeOpenVPN("old"))
	charon := withCharonCmd(t, h, fakeCharonCmd("old"))
	h.check()
	if h.restarts.Load() != 1 {
		t.Fatalf("not installed: %+v", h.u.Status())
	}
	if !fileIs(t, ovpn, fakeOpenVPN("new")) || !fileIs(t, charon, fakeCharonCmd("new")) ||
		!fileIs(t, prevBinary(charon), fakeCharonCmd("old")) {
		t.Fatal("helpers not both replaced (and kept)")
	}
	if ps, _ := loadPersisted(h.env.StateDir); ps.OpenVPNSwap != helperReplaced || ps.HelperSwap["charon-cmd"] != helperReplaced {
		t.Fatalf("swaps recorded as %q %v", ps.OpenVPNSwap, ps.HelperSwap)
	}

	env := guardEnv(h, "0.2.7")
	for i := 0; i <= maxBoots; i++ {
		_, _ = BootGuard(env)
	}
	if !fileIs(t, h.env.Binary, fakeDaemon("0.2.6")) || !fileIs(t, ovpn, fakeOpenVPN("old")) || !fileIs(t, charon, fakeCharonCmd("old")) {
		t.Fatal("daemon and helpers not all rolled back")
	}
	if ps, _ := loadPersisted(h.env.StateDir); ps.OpenVPNSwap != "" || ps.HelperSwap != nil {
		t.Fatalf("swaps still recorded: %q %v", ps.OpenVPNSwap, ps.HelperSwap)
	}
}

// The first release with charon-cmd adds it; a rollback keeps it, and an
// update whose release lacks it leaves the installed one alone.
func TestFirstShippedCharonCmdIsKept(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	f.tgz = macReleaseWith(t, "0.2.7", fakeOpenVPN("new"), fakeCharonCmd("new"))
	h := newHarness(t, f, "0.2.6")
	withOpenVPN(t, h, fakeOpenVPN("old"))
	charon := withCharonCmd(t, h, nil)
	h.check()
	if !fileIs(t, charon, fakeCharonCmd("new")) || fileExists(prevBinary(charon)) {
		t.Fatal("charon-cmd not added (or a .prev invented)")
	}
	for i := 0; i <= maxBoots; i++ {
		_, _ = BootGuard(guardEnv(h, "0.2.7"))
	}
	if !fileIs(t, h.env.Binary, fakeDaemon("0.2.6")) || !fileIs(t, charon, fakeCharonCmd("new")) {
		t.Fatal("the rollback removed the charon-cmd the update added")
	}
}

// A daemon an older updater installed (one that knew only openvpn) gets the
// charon-cmd its release ships; the openvpn in place isn't touched.
func TestMissingCharonCmdIsRepaired(t *testing.T) {
	f := newFakeRelease(t, "0.3.0", fakeDaemon("0.3.0"))
	f.tgz = macReleaseWith(t, "0.3.0", fakeOpenVPN("shipped"), fakeCharonCmd("shipped"))
	h := newHarness(t, f, "0.3.0")
	ovpn := withOpenVPN(t, h, fakeOpenVPN("mine"))
	charon := withCharonCmd(t, h, nil)
	h.check()
	if !fileIs(t, charon, fakeCharonCmd("shipped")) || !fileIs(t, ovpn, fakeOpenVPN("mine")) || !fileIs(t, h.env.Binary, fakeDaemon("0.3.0")) {
		t.Fatal("charon-cmd not repaired, or something else touched")
	}
	n := f.downloads.Load()
	h.check()
	if f.downloads.Load() != n {
		t.Fatal("downloaded again with both in place")
	}
}

// A release without charon-cmd is given up on for charon-cmd alone, once;
// a missing openvpn still comes from it.
func TestRepairGivesUpPerHelper(t *testing.T) {
	f := newFakeRelease(t, "0.3.0", fakeDaemon("0.3.0"))
	f.tgz = macReleaseWith(t, "0.3.0", fakeOpenVPN("shipped"), nil)
	h := newHarness(t, f, "0.3.0")
	ovpn := withOpenVPN(t, h, nil)
	charon := withCharonCmd(t, h, nil)
	h.check()
	h.check()
	if !fileIs(t, ovpn, fakeOpenVPN("shipped")) || fileExists(charon) {
		t.Fatal("openvpn should be repaired, charon-cmd absent")
	}
	if n := f.downloads.Load(); n != 1 {
		t.Fatalf("downloaded %d times", n)
	}
	if ps, _ := loadPersisted(h.env.StateDir); ps.HelperRepair["charon-cmd"] != "0.3.0" || ps.OpenVPNRepair != "" {
		t.Fatalf("gave up on %v / %q", ps.HelperRepair, ps.OpenVPNRepair)
	}
}

// A release whose charon-cmd doesn't run here is broken: skipped, nothing
// replaced.
func TestReleaseWhoseCharonCmdDoesntRunIsSkipped(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	f.tgz = macReleaseWith(t, "0.2.7", fakeOpenVPN("new"), []byte("#!/bin/sh\nexit 3\n"))
	h := newHarness(t, f, "0.2.6")
	ovpn := withOpenVPN(t, h, fakeOpenVPN("old"))
	charon := withCharonCmd(t, h, fakeCharonCmd("old"))
	h.check()
	if ps, _ := loadPersisted(h.env.StateDir); ps.Skip != "0.2.7" {
		t.Fatal("a release with a broken charon-cmd wasn't skipped")
	}
	if !fileIs(t, ovpn, fakeOpenVPN("old")) || !fileIs(t, charon, fakeCharonCmd("old")) || !fileIs(t, h.env.Binary, fakeDaemon("0.2.6")) {
		t.Fatal("something was replaced")
	}
}
