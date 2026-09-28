package tunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
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

// The first management hold is released at once; the hold stays on (so a
// daemon that dies leaves openvpn parked in it), and a restart's hold is
// released only after the backoff — never back to back.
func TestLaterHoldsWaitForTheBackoff(t *testing.T) {
	defer func(d time.Duration) { holdBackoffMin = d }(holdBackoffMin)
	holdBackoffMin = 150 * time.Millisecond
	h := newHarness(t, func(f *FakeLauncher) { f.HangUp = true })
	if _, err := h.m.Save(context.Background(), infraSpec()); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelFailed)
	if d := time.Since(start); d < time.Duration(maxFailedAttempts-1)*holdBackoffMin {
		t.Fatalf("%d attempts in %s: retried without the backoff", maxFailedAttempts, d)
	}
	cmds := h.fl.Commands()
	if slices.Contains(cmds, "hold off") {
		t.Fatalf("the hold must stay on: %q", cmds)
	}
	if n := count(cmds, "hold release"); n != maxFailedAttempts {
		t.Fatalf("hold released %d times for %d attempts", n, maxFailedAttempts)
	}
}

// A server that hangs up after every login (an old server's answer to a wrong
// password) is given up on after a few attempts, with the likely cause.
func TestGivesUpOnAServerThatKeepsHangingUp(t *testing.T) {
	defer func(d time.Duration) { holdBackoffMin = d }(holdBackoffMin)
	holdBackoffMin = 10 * time.Millisecond
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

// A tunnel whose address can't be found on any interface can't be checked
// (a pushed IPv6-only configuration, say): it's refused, not left connected.
func TestUnfindableTunnelInterfaceIsRefused(t *testing.T) {
	h := newHarness(t)
	h.m.o.Ifaces = func(context.Context) ([]domain.Iface, error) { return nil, nil }
	if _, err := h.m.Save(context.Background(), infraSpec()); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, h.m, "infra", domain.TunnelFailed)
	if !strings.Contains(st.LastError, "no interface holds") {
		t.Fatalf("last error = %q", st.LastError)
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
	time.Sleep(200 * time.Millisecond)                                // let the trap install
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

// One unreadable definition must not stop the daemon: the manager starts,
// lists it as failed with what to do, and deleting it removes the file.
func TestUnreadableDefinitionIsListedNotFatal(t *testing.T) {
	h := newHarness(t)
	if _, err := h.m.Save(context.Background(), infraSpec()); err != nil {
		t.Fatal(err)
	}
	h.m.Shutdown()
	if err := os.WriteFile(filepath.Join(h.dir, "broken.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := New(Options{Dir: h.dir, Launcher: h.fl, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatalf("one bad file stopped the manager: %v", err)
	}
	t.Cleanup(m.Shutdown)
	st, ok := m.Status("broken")
	if !ok || st.State != domain.TunnelFailed || !strings.Contains(st.LastError, "can't be read") {
		t.Fatalf("broken tunnel status = %+v, %v", st, ok)
	}
	if len(m.List()) != 2 {
		t.Fatalf("list = %+v", m.List())
	}
	if err := m.Delete(context.Background(), "broken"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "broken.json")); !os.IsNotExist(err) {
		t.Fatal("broken definition file not removed")
	}
}

// A pushed ifconfig whose peer is outside the tunnel's own /30 (here, the LAN
// router) puts a host route to it into the tunnel: the connection is refused.
func TestRefusesAStrayRouteIntoTheTunnel(t *testing.T) {
	for _, tc := range []struct {
		dst    string
		refuse bool
	}{
		{"10.99.0.0/24", false},  // the tunnel's own subnet
		{"10.99.0.1/32", false},  // its net30 peer
		{"224.0.0.0/4", false},   // multicast plumbing
		{"192.168.1.1/32", true}, // the LAN router
		{"8.8.8.8/32", true},     // someone's DNS
		{"10.0.0.0/8", true},     // wider than its network
		{"169.254.169.254/32", true},
	} {
		h := newHarness(t)
		h.m.o.Routes = func(context.Context) ([]domain.Route, error) {
			return []domain.Route{{DstCIDR: tc.dst, Iface: "utun9", Family: domain.FamilyV4, Owner: domain.OwnerSystem}}, nil
		}
		if _, err := h.m.Save(context.Background(), infraSpec()); err != nil {
			t.Fatal(err)
		}
		if err := h.m.Connect("infra"); err != nil {
			t.Fatal(err)
		}
		if tc.refuse {
			st := waitState(t, h.m, "infra", domain.TunnelFailed)
			if !strings.Contains(st.LastError, strings.TrimSuffix(tc.dst, "/32")) {
				t.Errorf("%s: last error = %q", tc.dst, st.LastError)
			}
		} else {
			waitState(t, h.m, "infra", domain.TunnelConnected)
		}
		h.m.Shutdown()
	}
}

func TestOurCommandLine(t *testing.T) {
	const run = "/var/db/riftroute/tunnels"
	for _, tc := range []struct {
		args, bin string
		want      bool
	}{
		{"/Library/PrivilegedHelperTools/riftroute-openvpn --config /var/db/riftroute/tunnels/infra.ovpn", "/Library/PrivilegedHelperTools/riftroute-openvpn", true},
		{"/usr/sbin/openvpn --config /var/db/riftroute/tunnels/infra.ovpn", "/usr/sbin/openvpn", true},
		{"/Library/PrivilegedHelperTools/riftroute-openvpn --config /var/db/riftroute/tunnels/infra.ovpn", "", true}, // an older pid file
		{"/tmp/openvpn --config /var/db/riftroute/tunnels/infra.ovpn", "/usr/sbin/openvpn", false},                   // not the recorded binary
		{"/usr/sbin/openvpn --config /home/me/work.ovpn", "/usr/sbin/openvpn", false},                                // someone else's config
		{"/usr/bin/sleep 30 --config /var/db/riftroute/tunnels/x", "", false},                                        // not openvpn
		{"", "/usr/sbin/openvpn", false}, // gone
	} {
		if got := ourCommandLine(tc.args, tc.bin, run); got != tc.want {
			t.Errorf("ourCommandLine(%q, %q) = %v", tc.args, tc.bin, got)
		}
	}
}

// On a reconnect the tunnel's own routes are still on its (persisted)
// interface, and macOS doesn't mark them as RiftRoute's: they aren't stray.
func TestOwnRoutesOnTheTunnelAreNotStray(t *testing.T) {
	h := newHarness(t)
	h.m.o.Routes = func(context.Context) ([]domain.Route, error) {
		return []domain.Route{
			{DstCIDR: "192.168.70.0/24", Iface: "utun9", Family: domain.FamilyV4, Owner: domain.OwnerSystem},
			{DstCIDR: "192.168.72.11/32", Iface: "utun9", Family: domain.FamilyV4, Owner: domain.OwnerSystem},
		}, nil
	}
	if _, err := h.m.Save(context.Background(), infraSpec()); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
}

// On macOS a tunnel-mode profile's routes stay on the tunnel's interface
// across an openvpn restart, untagged: they're RiftRoute's own (the
// ownership map says so), not routes the server pushed — the tunnel isn't
// refused on its reconnect. One RiftRoute didn't install still is.
func TestProfileRoutesOnTheTunnelAreNotStray(t *testing.T) {
	h := newHarness(t)
	h.m.o.Routes = func(context.Context) ([]domain.Route, error) {
		return []domain.Route{
			{DstCIDR: "192.168.70.0/24", Iface: "utun9", Family: domain.FamilyV4, Owner: domain.OwnerVPN},
			{DstCIDR: "10.50.0.0/16", Iface: "utun9", Family: domain.FamilyV4, Owner: domain.OwnerVPN},
		}, nil
	}
	h.m.o.Owned = func() []domain.ManagedRoute {
		return []domain.ManagedRoute{
			{Route: domain.Route{DstCIDR: "10.50.0.0/16", Iface: "utun9", Family: domain.FamilyV4}, ProfileID: "tunnel:infra"},
			// Another tunnel's, and a pin (via a gateway), don't count.
			{Route: domain.Route{DstCIDR: "10.60.0.0/16", Iface: "utun7", Family: domain.FamilyV4}, ProfileID: "tunnel:other"},
			{Route: domain.Route{DstCIDR: "10.70.0.0/16", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4}, ProfileID: "tunnel:infra"},
		}
	}
	if _, err := h.m.Save(context.Background(), infraSpec()); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
	if err := h.m.Disconnect(context.Background(), "infra"); err != nil {
		t.Fatal(err)
	}

	// A route on the tunnel RiftRoute didn't install is still the server's.
	h.m.o.Owned = func() []domain.ManagedRoute { return nil }
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, h.m, "infra", domain.TunnelFailed)
	if !strings.Contains(st.LastError, "10.50.0.0/16") {
		t.Errorf("last error = %q", st.LastError)
	}
}

// Tunnels up when the daemon restarts into an update come back after it;
// ones the user disconnected don't.
func TestTunnelsComeBackAfterAnUpdateRestart(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.m.Save(ctx, infraSpec()); err != nil {
		t.Fatal(err)
	}
	other := infraSpec()
	other.Name = "other"
	if _, err := h.m.Save(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
	h.m.RememberForRestart(true)
	h.m.Shutdown()

	m2, err := New(Options{Dir: h.dir, Launcher: h.fl, Ifaces: h.m.o.Ifaces, Resolve: h.m.o.Resolve,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m2.Shutdown)
	m2.StartAuto()
	waitState(t, m2, "infra", domain.TunnelConnected)
	if st, _ := m2.Status("other"); st.State != domain.TunnelDisconnected {
		t.Fatalf("a tunnel that wasn't up came up: %+v", st)
	}
	// Only once: a later plain start doesn't reconnect it again.
	if _, err := os.Stat(filepath.Join(h.dir, resumeFile)); !os.IsNotExist(err) {
		t.Fatal("the resume list outlived its start")
	}
}

// A save racing a delete of the same tunnel is refused, not half-applied.
func TestSaveDuringDeleteIsRefused(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.m.Save(ctx, infraSpec()); err != nil {
		t.Fatal(err)
	}
	var saveErr error
	var armed atomic.Bool
	armed.Store(true)
	h.m.o.OnChange = func() {
		if armed.CompareAndSwap(true, false) {
			_, saveErr = h.m.Save(ctx, infraSpec())
		}
	}
	if err := h.m.Delete(ctx, "infra"); err != nil {
		t.Fatal(err)
	}
	if saveErr == nil || !strings.Contains(saveErr.Error(), "being deleted") {
		t.Fatalf("save during delete: %v", saveErr)
	}
	if _, ok := h.m.Status("infra"); ok {
		t.Fatal("the tunnel survived its delete")
	}
}

// A refused apply is retried until it goes through — never abandoned.
func TestApplierKeepsRetrying(t *testing.T) {
	defer func(a, b time.Duration) { applyRetryEvery, applyRetryMax = a, b }(applyRetryEvery, applyRetryMax)
	applyRetryEvery, applyRetryMax = time.Millisecond, 5*time.Millisecond
	var calls atomic.Int32
	a := newApplier(func(context.Context) error {
		if calls.Add(1) < 60 {
			return errors.New("an interactive change is awaiting confirmation")
		}
		return nil
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer a.close()
	a.request()
	waitFor(t, "the apply to go through", func() bool { return calls.Load() >= 60 })
}
