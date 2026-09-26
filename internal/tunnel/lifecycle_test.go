package tunnel

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// A connect that lands between Delete's disconnect and its removal of the
// definition must be refused: it would start an openvpn nothing tracks.
func TestConnectDuringDeleteIsRefused(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.m.Save(ctx, infraSpec()); err != nil {
		t.Fatal(err)
	}
	var armed atomic.Bool
	var connectErr error
	armed.Store(true)
	h.m.o.OnChange = func() { // runs inside Delete, after its disconnect
		if armed.CompareAndSwap(true, false) {
			connectErr = h.m.Connect("infra")
		}
	}
	if err := h.m.Delete(ctx, "infra"); err != nil {
		t.Fatal(err)
	}
	if connectErr == nil {
		t.Fatal("a connect during the delete was accepted")
	}
	time.Sleep(50 * time.Millisecond)
	if n := h.fl.Running(); n != 0 {
		t.Fatalf("%d openvpn running for a deleted tunnel", n)
	}
}

// The first management hold is released once and the hold turned off, so a
// restart gets openvpn's own backoff — not an immediate retry.
func TestHoldIsReleasedOnceAndTurnedOff(t *testing.T) {
	h := newHarness(t)
	if _, err := h.m.Save(context.Background(), infraSpec()); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
	cmds := h.fl.Commands()
	if n := count(cmds, "hold release"); n != 1 {
		t.Fatalf("hold released %d times: %q", n, cmds)
	}
	if i, j := slices.Index(cmds, "hold off"), slices.Index(cmds, "hold release"); i < 0 || i > j {
		t.Fatalf("the hold must be turned off before the release: %q", cmds)
	}
}

// A server that hangs up after every login (an old server's answer to a wrong
// password) is given up on after a few attempts, with the likely cause.
func TestGivesUpOnAServerThatKeepsHangingUp(t *testing.T) {
	h := newHarness(t, func(f *FakeLauncher) { f.HangUp = true })
	if _, err := h.m.Save(context.Background(), infraSpec()); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, h.m, "infra", domain.TunnelFailed)
	if !strings.Contains(st.LastError, "attempts") {
		t.Fatalf("last error = %q", st.LastError)
	}
	if n := count(h.fl.Commands(), `username "Auth" "alice"`); n != maxFailedAttempts {
		t.Fatalf("logged in %d times, want %d", n, maxFailedAttempts)
	}
}

// A server that gives the tunnel a network wider than /16 would capture
// traffic beyond the listed routes: the connection is refused.
func TestRefusesAWideTunnelNetwork(t *testing.T) {
	h := newHarness(t)
	h.mu.Lock()
	h.bits = 8
	h.mu.Unlock()
	if _, err := h.m.Save(context.Background(), infraSpec()); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, h.m, "infra", domain.TunnelFailed)
	if !strings.Contains(st.LastError, "10.0.0.0/8") {
		t.Fatalf("last error = %q", st.LastError)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, in := range h.applies {
		for _, ti := range in {
			if ti.Iface != "" {
				t.Fatalf("routes were installed into a refused tunnel: %+v", ti)
			}
		}
	}
}

// An openvpn that exits at once (a config it refused) fails the tunnel
// promptly instead of after the management dial's timeout.
func TestOpenVPNExitingAtStartFailsFast(t *testing.T) {
	h := newHarness(t, func(f *FakeLauncher) { f.ExitAtStart = true })
	if _, err := h.m.Save(context.Background(), infraSpec()); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, h.m, "infra", domain.TunnelFailed)
	if time.Since(start) > 3*time.Second || !strings.Contains(st.LastError, "Options error") {
		t.Fatalf("took %s: %q", time.Since(start), st.LastError)
	}
}

// A saved password is only sent to the servers it was entered for.
func TestSavedPasswordNeedsReentryForNewServers(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.m.Save(ctx, infraSpec()); err != nil {
		t.Fatal(err)
	}
	moved := infraSpec()
	moved.Password = ""
	moved.Config = strings.Replace(pushProfile, "198.51.100.7", "203.0.113.66", 1)
	_, err := h.m.Save(ctx, moved)
	var ve *ValidationError
	if !errors.As(err, &ve) || !strings.Contains(err.Error(), "enter the password again") {
		t.Fatalf("saving new servers without the password: %v", err)
	}
	moved.Password = "pw"
	if _, err := h.m.Save(ctx, moved); err != nil {
		t.Fatal(err)
	}
	// Changing only the routes keeps it.
	routesOnly := moved
	routesOnly.Password, routesOnly.Config = "", ""
	routesOnly.Routes = []string{"192.168.70.0/24"}
	if st, err := h.m.Save(ctx, routesOnly); err != nil || !st.HasPassword {
		t.Fatalf("routes-only edit: %+v %v", st, err)
	}
}

// Shutdown must not stall on a route apply that can't run (the updater holds
// the Apply Protocol until the daemon exits).
func TestShutdownDoesNotWaitOnABlockedApply(t *testing.T) {
	h := newHarness(t)
	if _, err := h.m.Save(context.Background(), infraSpec()); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
	defer func(d time.Duration) { shutdownApplyWait = d }(shutdownApplyWait)
	shutdownApplyWait = 300 * time.Millisecond
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	h.m.o.Apply = func(ctx context.Context) error { <-block; return nil }
	start := time.Now()
	h.m.Shutdown()
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("Shutdown took %s", d)
	}
	if n := h.fl.Running(); n != 0 {
		t.Fatalf("%d openvpn still running", n)
	}
}

// Reaping an openvpn left by a crashed daemon escalates to SIGKILL when it
// ignores SIGTERM, and never signals a process that isn't ours any more.
func TestStopProcessEscalatesAndChecksIdentity(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", `trap "" TERM; while :; do sleep 1; done`)
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	time.Sleep(200 * time.Millisecond) // let the trap install
	_ = stopProcess(cmd.Process.Pid, func(int) bool { return false }) // not ours: left alone
	select {
	case <-done:
		t.Fatal("a process that isn't ours was signalled")
	default:
	}
	if !stopProcess(cmd.Process.Pid, func(int) bool { return true }) {
		t.Fatal("a SIGTERM-ignoring process survived")
	}
	<-done
}

func TestParseHold(t *testing.T) {
	for body, want := range map[string]time.Duration{
		"Waiting for hold release:0":  0,
		"Waiting for hold release:25": 25 * time.Second,
		"Waiting for hold release":    0,
		"Waiting for hold release:x":  0,
	} {
		if got := parseHold(body); got != want {
			t.Errorf("parseHold(%q) = %s, want %s", body, got, want)
		}
	}
}

func TestShortRunDirIsStableAndPrivate(t *testing.T) {
	a, err := shortRunDir("/some/very/long/dir")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := shortRunDir("/some/very/long/dir")
	c, _ := shortRunDir("/another/dir")
	if a != b || a == c {
		t.Fatalf("run dirs: %s %s %s", a, b, c)
	}
}

func count(xs []string, x string) int {
	n := 0
	for _, v := range xs {
		if v == x {
			n++
		}
	}
	return n
}
