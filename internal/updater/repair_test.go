package updater

import (
	"os"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

// A daemon an older updater installed without its openvpn gets the one its
// own release ships, from that signed release.
func TestMissingOpenVPNIsRepairedFromTheRunningRelease(t *testing.T) {
	f := newFakeRelease(t, "0.3.0", fakeDaemon("0.3.0"))
	f.tgz = macRelease(t, "0.3.0", fakeOpenVPN("shipped"))
	h := newHarness(t, f, "0.3.0")
	ovpn := withOpenVPN(t, h, nil)
	h.check()
	if !fileIs(t, ovpn, fakeOpenVPN("shipped")) {
		t.Fatal("openvpn not repaired")
	}
	if fi, _ := os.Stat(ovpn); fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if !fileIs(t, h.env.Binary, fakeDaemon("0.3.0")) {
		t.Fatal("the repair must never touch the daemon")
	}
	if fileExists(stagingDir(h.env.StateDir)) {
		entries, _ := os.ReadDir(stagingDir(h.env.StateDir))
		if len(entries) != 0 {
			t.Fatal("repair files left behind")
		}
	}
	// Present now: no more downloads.
	n := f.downloads.Load()
	h.check()
	if f.downloads.Load() != n {
		t.Fatal("downloaded again with openvpn in place")
	}
}

// A release that ships no openvpn (Linux, or one built without it) is tried
// once, not at every check.
func TestRepairGivesUpOnAReleaseWithoutOpenVPN(t *testing.T) {
	f := newFakeRelease(t, "0.3.0", fakeDaemon("0.3.0"))
	f.tgz = macRelease(t, "0.3.0", nil)
	h := newHarness(t, f, "0.3.0")
	ovpn := withOpenVPN(t, h, nil)
	h.check()
	h.check()
	if fileExists(ovpn) {
		t.Fatal("something was installed")
	}
	if n := f.downloads.Load(); n != 1 {
		t.Fatalf("downloaded %d times", n)
	}
}

// Only the running version's release repairs: an older daemon waits for the
// update, which brings openvpn with it.
func TestRepairOnlyFromTheRunningVersion(t *testing.T) {
	f := newFakeRelease(t, "0.3.1", fakeDaemon("0.3.1"))
	f.tgz = macRelease(t, "0.3.1", fakeOpenVPN("newer"))
	h := newHarness(t, f, "0.3.0")
	h.mode.Store(domain.UpdateNotify) // not installing 0.3.1 here
	ovpn := withOpenVPN(t, h, nil)
	h.check()
	if fileExists(ovpn) {
		t.Fatal("repaired from another version's release")
	}
}
