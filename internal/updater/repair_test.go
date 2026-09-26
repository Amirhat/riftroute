package updater

import (
	"context"
	"os"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/update"
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
// once, not at every check; a newer release is tried again.
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
	if ps, _ := loadPersisted(h.env.StateDir); ps.OpenVPNRepair != "0.3.0" {
		t.Fatalf("gave up on %q", ps.OpenVPNRepair)
	}

	f.version, f.tgz = "0.3.1", macRelease(t, "0.3.1", fakeOpenVPN("0.3.1"))
	h.mode.Store(domain.UpdateNotify) // repaired, not updated
	h.check()
	if !fileIs(t, ovpn, fakeOpenVPN("0.3.1")) || !fileIs(t, h.env.Binary, fakeDaemon("0.3.0")) {
		t.Fatal("a newer release with openvpn wasn't tried")
	}
}

// Whatever holds the daemon back from the newest release — a rollout that
// hasn't reached it, a skipped version, updates in notify mode or off — a
// missing openvpn still comes from that release: every openvpn RiftRoute
// ships runs every daemon's tunnels. Only openvpn is taken. (Not a halt:
// see TestRepairNeverFromAHaltedRelease.)
func TestRepairTakesOpenVPNFromANewerReleaseItIsHeldBackFrom(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(*fakeRelease, *harness)
		job   jobKind
	}{
		{"notify", func(_ *fakeRelease, h *harness) { h.mode.Store(domain.UpdateNotify) }, jobAuto},
		{"off, check now", func(_ *fakeRelease, h *harness) { h.mode.Store(domain.UpdateOff) }, jobManual},
		{"not in the rollout yet", func(f *fakeRelease, h *harness) {
			f.advice = update.Advice{RolloutPercent: 0}
		}, jobAuto},
		{"skipped", func(_ *fakeRelease, h *harness) {
			h.u.save(func(ps *persisted) { ps.Skip = "0.3.1" })
		}, jobAuto},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeRelease(t, "0.3.1", fakeDaemon("0.3.1"))
			f.tgz = macRelease(t, "0.3.1", fakeOpenVPN("newer"))
			h := newHarness(t, f, "0.3.0")
			ovpn := withOpenVPN(t, h, nil)
			c.setup(f, h)
			h.u.runJob(context.Background(), c.job, nil)
			if !fileIs(t, ovpn, fakeOpenVPN("newer")) {
				t.Fatalf("openvpn not repaired from the newer release: %+v", h.u.Status())
			}
			if !fileIs(t, h.env.Binary, fakeDaemon("0.3.0")) || h.restarts.Load() != 0 || h.u.Status().Staged != "" {
				t.Fatalf("the repair updated the daemon: %+v", h.u.Status())
			}
		})
	}
}

// An update being installed brings its openvpn with it: the release isn't
// downloaded twice, and the swap records the openvpn as added.
func TestAnUpdateBringsTheMissingOpenVPNItself(t *testing.T) {
	h, ovpn := installedWithOpenVPN(t, nil)
	if !fileIs(t, ovpn, fakeOpenVPN("new")) || fileExists(prevBinary(ovpn)) {
		t.Fatal("openvpn not added by the update (or a .prev invented)")
	}
	if ps, _ := loadPersisted(h.env.StateDir); ps.OpenVPNSwap != openvpnAdded {
		t.Fatalf("swap recorded as %q", ps.OpenVPNSwap)
	}
}

// "Check now" answers once the missing openvpn is in place, so the app can
// look again straight away.
func TestCheckNowAnswersAfterTheRepair(t *testing.T) {
	f := newFakeRelease(t, "0.3.0", fakeDaemon("0.3.0"))
	f.tgz = macRelease(t, "0.3.0", fakeOpenVPN("shipped"))
	h := newHarness(t, f, "0.3.0")
	h.mode.Store(domain.UpdateOff)
	ovpn := withOpenVPN(t, h, nil)
	h.u.CheckNow()
	if !fileIs(t, ovpn, fakeOpenVPN("shipped")) {
		t.Fatal("check now returned before openvpn was repaired")
	}
	h.u.wait()
}

// A halt may be about the release's openvpn itself: the repair doesn't take
// one from a halted release.
func TestRepairNeverFromAHaltedRelease(t *testing.T) {
	f := newFakeRelease(t, "0.3.1", fakeDaemon("0.3.1"))
	f.tgz = macRelease(t, "0.3.1", fakeOpenVPN("halted"))
	f.advice = update.Advice{RolloutPercent: 100, Halt: true}
	h := newHarness(t, f, "0.3.0")
	ovpn := withOpenVPN(t, h, nil)
	h.check()
	if fileExists(ovpn) || f.downloads.Load() != 0 {
		t.Fatal("openvpn taken from a halted release")
	}
}
