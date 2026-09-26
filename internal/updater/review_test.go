package updater

// Tests for the adversarial review's findings (2026-09-26).

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/update"
)

// #1: a self-test cut short (cancelled, timed out) or an I/O error is not the
// release's fault: it must not be skipped.
func TestInterruptedSelfTestDoesNotSkipTheRelease(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	h := newHarness(t, f, "0.2.6")
	ctx, cancel := context.WithCancel(context.Background())
	h.selfHook = cancel
	h.u.runJob(ctx, jobAuto, nil)
	h.selfHook = nil
	if ps, _ := loadPersisted(h.env.StateDir); ps.Skip != "" {
		t.Fatalf("interrupted self-test skipped %s", ps.Skip)
	}
	h.selfErr = errors.New("disk full")
	h.check()
	h.selfErr = nil
	if ps, _ := loadPersisted(h.env.StateDir); ps.Skip != "" {
		t.Fatalf("an I/O error skipped %s", ps.Skip)
	}
	if st := h.check(); st.Staged != "0.2.7" && st.State != "installing" {
		t.Fatalf("release not staged on retry: %+v", st)
	}
}

// "Check now" returns with the verdict while the work continues on the
// daemon's lifetime, not the request's.
func TestCheckNowReturnsTheVerdictAndKeepsWorking(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	h := newHarness(t, f, "0.2.6")
	h.idle.Store(false)
	st := h.u.CheckNow()
	if st.Latest != "0.2.7" || st.Action != "install" {
		t.Fatalf("verdict: %+v", st)
	}
	h.u.wait()
	if st := h.u.Status(); st.Staged != "0.2.7" {
		t.Fatalf("staging didn't finish in the background: %+v", st)
	}
}

// #2: staging a newer release that then fails must not leave the old pointer
// aimed at the new file.
func TestAFailedNewerReleaseLeavesNothingStaged(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	h := newHarness(t, f, "0.2.6")
	h.idle.Store(false)
	if st := h.check(); st.Staged != "0.2.7" {
		t.Fatalf("setup: %+v", st)
	}
	f.version, f.tgz = "0.2.8", tarball(t, "riftrouted", fakeDaemon("0.2.8"))
	h.selfErr = exitError(t)
	h.check()
	h.selfErr = nil
	h.idle.Store(true)
	h.tick()
	if h.restarts.Load() != 0 {
		t.Fatal("installed something after the newer release failed its self-test")
	}
	if b, _ := os.ReadFile(h.env.Binary); !bytes.Equal(b, fakeDaemon("0.2.6")) {
		t.Fatal("binary replaced")
	}
}

// #3: a halt after staging stops the install — at the next check, and at the
// last look before swapping.
func TestHaltAfterStagingStopsTheInstall(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	h := newHarness(t, f, "0.2.6")
	h.idle.Store(false)
	h.check()
	f.advice = update.Advice{RolloutPercent: 100, Halt: true}
	h.idle.Store(true)
	h.tick() // the last look before swapping sees the halt
	if h.restarts.Load() != 0 {
		t.Fatal("installed a halted release")
	}
	if st := h.u.Status(); st.Staged != "" || st.Action != "hold" {
		t.Fatalf("after halt: %+v", st)
	}
}

// #4: once swapped, nothing may swap again before the restart.
func TestNoSecondSwapBeforeTheRestart(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	h := newHarness(t, f, "0.2.6")
	h.check() // stages and installs (quiet)
	if h.restarts.Load() != 1 {
		t.Fatal("setup: not installed")
	}
	h.tick()
	h.check()
	if b, _ := os.ReadFile(prevBinary(h.env.Binary)); !bytes.Equal(b, fakeDaemon("0.2.6")) {
		t.Fatal(".prev overwritten by a second swap")
	}
	if _, ok := readMarker(h.env.StateDir); !ok {
		t.Fatal("probation marker lost")
	}
	if h.held.Load() != 1 {
		t.Fatalf("the apply lock must stay held until the restart (held=%d)", h.held.Load())
	}
}

// #5: a rollback that can't be done doesn't turn into an endless restart loop.
func TestFailedRollbackDoesNotLoop(t *testing.T) {
	h := installed(t)
	env := guardEnv(h, "0.2.7")
	_ = os.Remove(prevBinary(h.env.Binary)) // nothing to go back to
	for i := 0; i < maxBoots; i++ {
		_, _ = BootGuard(env)
	}
	g, err := BootGuard(env)
	if err == nil || g.RestartNow {
		t.Fatalf("want a recorded failure and no restart: %v %+v", err, g)
	}
	if _, ok := readMarker(h.env.StateDir); ok {
		t.Fatal("marker left: the next start would try again")
	}
	h.env.Current = "0.2.7"
	u2, _ := New(h.env)
	if st := u2.Status(); !strings.Contains(st.Error, "rolling back failed") {
		t.Fatalf("failure not reported: %+v", st)
	}
}

// #11: a crash between the marker and the rename changed nothing: the
// release must not be skipped.
func TestCrashBeforeTheRenameDoesNotSkip(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	h := newHarness(t, f, "0.2.6")
	if err := writeMarker(h.env.StateDir, marker{From: "0.2.6", To: "0.2.7", At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if g, err := BootGuard(guardEnv(h, "0.2.6")); err != nil || g.RestartNow {
		t.Fatalf("%v %+v", err, g)
	}
	if ps, _ := loadPersisted(h.env.StateDir); ps.Skip != "" || ps.RolledBackFrom != "" {
		t.Fatalf("release skipped after a crash that changed nothing: %+v", ps)
	}
}

// #12: the updater's writes don't undo what Confirm recorded.
func TestConfirmSurvivesTheUpdatersWrites(t *testing.T) {
	h := installed(t)
	g, _ := BootGuard(guardEnv(h, "0.2.7"))
	h.env.Current = "0.2.7"
	u2, _ := New(h.env) // built before Confirm, as in the daemon
	g.OnConfirm = u2.Reload
	g.Confirm()
	u2.runJob(context.Background(), jobAuto, nil) // saves LastCheck
	ps, _ := loadPersisted(h.env.StateDir)
	if ps.InstalledAt.IsZero() {
		t.Fatal("InstalledAt lost to a stale write")
	}
	if u2.Status().InstalledAt.IsZero() {
		t.Fatal("status not refreshed after Confirm")
	}
}

// Confirm never deletes a rollback the user asked for in the meantime.
func TestConfirmKeepsAUserRollbackRequest(t *testing.T) {
	h := installed(t)
	g, _ := BootGuard(guardEnv(h, "0.2.7"))
	_ = writeMarker(h.env.StateDir, marker{From: "0.2.7", To: "0.2.7", Rollback: true})
	g.Confirm()
	if m, ok := readMarker(h.env.StateDir); !ok || !m.Rollback {
		t.Fatal("Confirm removed the user's rollback request")
	}
}

// #8: the GitHub copy obeys the server's last word; one the server never
// advised on waits out the grace period.
func TestFallbackObeysLastAdviceAndGrace(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	h := newHarness(t, f, "0.2.6")
	h.idle.Store(false)
	f.advice = update.Advice{RolloutPercent: 100, Halt: true}
	h.check() // the server says halt
	f.serverDown.Store(true)
	if st := h.check(); st.Source != "github" || st.Action != "hold" {
		t.Fatalf("halt forgotten on fallback: %+v", st)
	}

	f2 := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	f2.serverDown.Store(true)
	h2 := newHarness(t, f2, "0.2.6")
	h2.idle.Store(false)
	h2.u.env.Now = func() time.Time { return time.Unix(0, 0).Add(24 * time.Hour) } // a day after publishing
	if st := h2.check(); st.Action != "hold" || !strings.Contains(st.Reason, "hasn't confirmed") {
		t.Fatalf("unconfirmed GitHub release within grace: %+v", st)
	}
	h2.u.env.Now = func() time.Time { return time.Unix(0, 0).Add(8 * 24 * time.Hour) }
	if st := h2.check(); st.Action != "install" {
		t.Fatalf("after the grace period: %+v", st)
	}
}

// #15: turning updates off cancels a pending "install now".
func TestTurningUpdatesOffCancelsInstallNow(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	h := newHarness(t, f, "0.2.6")
	h.mode.Store(domain.UpdateNotify)
	h.idle.Store(false)
	if _, err := h.u.InstallNow(); err != nil {
		t.Fatal(err)
	}
	h.u.wait()
	h.mode.Store(domain.UpdateOff)
	h.idle.Store(true)
	h.tick()
	if h.restarts.Load() != 0 {
		t.Fatal("installed after updates were turned off")
	}
}

// A user rollback waits for a quiet moment too.
func TestRollbackWaitsForAQuietMoment(t *testing.T) {
	h := installed(t)
	g, _ := BootGuard(guardEnv(h, "0.2.7"))
	g.Confirm()
	h.env.Current = "0.2.7"
	u2, _ := New(h.env)
	h.idle.Store(false)
	if err := u2.RequestRollback(); err == nil || !strings.Contains(err.Error(), "try again") {
		t.Fatalf("rollback during a change: %v", err)
	}
}
