package tunnel

import (
	"context"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// The package's tests never probe the network: a full tunnel's liveness is
// looked at only where a test asks for it.
func init() { defaultAlive.every = time.Hour }

// fastAlive makes liveness quick, and the prober and this machine's path
// out the test's.
func fastAlive(t *testing.T, h *harness, alive, outside *atomic.Bool) *atomic.Int32 {
	t.Helper()
	// Its manager's own, set before its watcher starts (New's ticks hourly).
	h.m.at.every, h.m.at.first = 20*time.Millisecond, 50*time.Millisecond
	var asked atomic.Int32
	h.m.o.Probe = func(context.Context, []netip.Addr) bool {
		asked.Add(1)
		return alive.Load()
	}
	h.m.o.Routes = func(context.Context) ([]domain.Route, error) {
		if !outside.Load() {
			return nil, nil
		}
		return []domain.Route{{DstCIDR: "0.0.0.0/0", Gateway: "192.168.1.1", Iface: "en0"}}, nil
	}
	go h.m.watchAlive(h.m.at.every)
	return &asked
}

func fullSpec() domain.TunnelSpec {
	on := true
	s := infraSpec()
	s.AllTraffic = &on
	return s
}

// A full tunnel whose DNS answers through it stays; one that passes
// nothing is reconnected after its misses — failed for a moment, still
// wanted, then connected again; a tunnel that lists networks isn't looked
// at.
func TestFullTunnelThatPassesNothingIsReconnected(t *testing.T) {
	var alive, outside atomic.Bool
	alive.Store(true)
	outside.Store(true)
	h := newHarness(t)
	asked := fastAlive(t, h, &alive, &outside)
	ctx := context.Background()

	if _, err := h.m.Save(ctx, infraSpec()); err != nil {
		t.Fatal(err)
	}
	_ = h.m.Connect("infra")
	waitState(t, h.m, "infra", domain.TunnelConnected)
	time.Sleep(10 * h.m.at.every)
	if asked.Load() != 0 {
		t.Fatal("a tunnel that lists networks was probed")
	}

	if _, err := h.m.Save(ctx, fullSpec()); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
	waitFor(t, "probes", func() bool { return asked.Load() >= int32(2*h.m.at.misses) })
	if st, _ := h.m.Status("infra"); st.State != domain.TunnelConnected {
		t.Fatalf("reconnected though its DNS answers: %+v", st)
	}

	starts := h.fl.Starts()
	alive.Store(false)
	waitFor(t, "a reconnect", func() bool { return h.fl.Starts() > starts })
	waitState(t, h.m, "infra", domain.TunnelConnected)
	h.m.mu.Lock()
	want := h.m.rt["infra"].want
	h.m.mu.Unlock()
	if !want {
		t.Error("no longer wanted after the reconnect")
	}
}

// While this machine's own way out is down (asleep, rejoining Wi-Fi),
// nothing it asks gets through anything: no miss counts, and the tunnel
// stays. Traffic coming back through it is proof of life without asking.
func TestFullTunnelLivenessJudgesOnlyWhatItCan(t *testing.T) {
	var alive, outside atomic.Bool
	h := newHarness(t)
	asked := fastAlive(t, h, &alive, &outside)
	if _, err := h.m.Save(context.Background(), fullSpec()); err != nil {
		t.Fatal(err)
	}
	_ = h.m.Connect("infra")
	waitState(t, h.m, "infra", domain.TunnelConnected)
	starts := h.fl.Starts()
	waitFor(t, "probes", func() bool { return asked.Load() >= int32(3*h.m.at.misses) })
	if h.fl.Starts() != starts {
		t.Fatal("reconnected while this machine's way out was down")
	}

	outside.Store(true)
	stop := make(chan struct{})
	defer close(stop)
	go func() { // traffic comes back through it
		for {
			select {
			case <-stop:
				return
			case <-time.After(h.m.at.every / 2):
				h.m.update("infra", func(r *live) { r.in += 4096 })
			}
		}
	}()
	n := asked.Load()
	time.Sleep(10 * h.m.at.every)
	if h.fl.Starts() != starts {
		t.Fatal("reconnected though traffic comes back through it")
	}
	if asked.Load() > n+2 {
		t.Errorf("asked %d times though traffic comes back", asked.Load()-n)
	}
}

// The server down past what a fresh session tries (it gives up as a first
// connect does): the tunnel is connected again each time its session ends,
// still wanted, until the server is back — not left failed for good.
func TestFullTunnelRevivedAfterAnOutage(t *testing.T) {
	d := holdBackoffMin
	holdBackoffMin = 10 * time.Millisecond // a fresh session's attempts give up quickly
	t.Cleanup(func() { holdBackoffMin = d })
	var alive, outside atomic.Bool
	alive.Store(true)
	outside.Store(true)
	h := newHarness(t)
	fastAlive(t, h, &alive, &outside)
	if _, err := h.m.Save(context.Background(), fullSpec()); err != nil {
		t.Fatal(err)
	}
	_ = h.m.Connect("infra")
	waitState(t, h.m, "infra", domain.TunnelConnected)

	h.fl.SetHangUp(true) // the server goes down
	alive.Store(false)
	waitState(t, h.m, "infra", domain.TunnelFailed)
	starts := h.fl.Starts()
	waitFor(t, "another attempt after the session gave up", func() bool { return h.fl.Starts() > starts+1 })

	h.fl.SetHangUp(false) // and comes back
	alive.Store(true)
	waitState(t, h.m, "infra", domain.TunnelConnected)
	h.m.mu.Lock()
	want := h.m.rt["infra"].want
	h.m.mu.Unlock()
	if !want {
		t.Error("no longer wanted")
	}
}

// This machine's way out is a physical default: not a main VPN's (it stays
// while Wi-Fi is down), not RiftRoute's own (Model B's table), not in
// another family than the tunnel's servers.
func TestOutsideUpIsPhysical(t *testing.T) {
	h := newHarness(t)
	h.mu.Lock()
	h.ifaces = append(h.ifaces, domain.Iface{Name: "utun8", Up: true, IsVPN: true})
	h.mu.Unlock()
	v4 := []netip.Addr{netip.MustParseAddr("198.51.100.7")}
	for _, c := range []struct {
		r    domain.Route
		want bool
	}{
		{domain.Route{DstCIDR: "0.0.0.0/0", Gateway: "192.168.1.1", Iface: "en0"}, true},
		{domain.Route{DstCIDR: "0.0.0.0/0", Iface: "utun8"}, false},
		{domain.Route{DstCIDR: "0.0.0.0/0", Gateway: "10.8.0.1", Iface: "utun8"}, false},
		{domain.Route{DstCIDR: "0.0.0.0/0", Gateway: "192.168.1.1", Iface: "en0", Table: "5252"}, false},
		{domain.Route{DstCIDR: "0.0.0.0/0", Gateway: "192.168.1.1", Iface: "en0", Owner: domain.OwnerRiftRoute}, false},
		{domain.Route{DstCIDR: "::/0", Gateway: "fe80::1", Iface: "en0"}, false},
	} {
		h.m.o.Routes = func(context.Context) ([]domain.Route, error) { return []domain.Route{c.r}, nil }
		if got := h.m.outsideUp(context.Background(), []string{"utun9"}, v4); got != c.want {
			t.Errorf("%+v: %v", c.r, got)
		}
	}
}

// reviving reports whether name is in a reconnect cycle.
func reviving(h *harness, name string) bool {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	r := h.m.rt[name]
	return r != nil && r.alive.revive
}

// stillAt waits a while and fails if the engine was started again.
func stillAt(t *testing.T, starts func() int, n int, wait time.Duration) {
	t.Helper()
	time.Sleep(wait)
	if got := starts(); got != n {
		t.Fatalf("%d more attempts after the cycle should have stopped", got-n)
	}
}

// The stored password stops working while the tunnel is up; then liveness
// reconnects it. The rejected login isn't tried again and again (an
// account lockout): the cycle stops at it, failed, saying why.
func TestFullTunnelRevivalStopsAtARejectedLogin(t *testing.T) {
	var alive, outside atomic.Bool
	alive.Store(true)
	outside.Store(true)
	h := newHarness(t)
	fastAlive(t, h, &alive, &outside)
	if _, err := h.m.Save(context.Background(), fullSpec()); err != nil {
		t.Fatal(err)
	}
	_ = h.m.Connect("infra")
	waitState(t, h.m, "infra", domain.TunnelConnected)

	h.m.mu.Lock() // changed elsewhere (the company's portal), not here
	d := *h.m.defs["infra"]
	d.Password = "wrong"
	h.m.defs["infra"] = &d
	h.m.mu.Unlock()
	starts := h.fl.Starts()
	alive.Store(false)
	waitFor(t, "a reconnect", func() bool { return h.fl.Starts() > starts })
	st := waitState(t, h.m, "infra", domain.TunnelFailed)
	if !strings.Contains(st.LastError, "rejected the username or password") {
		t.Fatalf("failed with %q", st.LastError)
	}
	n := h.fl.Starts()
	stillAt(t, h.fl.Starts, n, 20*h.m.at.first)
	if n != starts+1 || reviving(h, "infra") {
		t.Fatalf("%d logins after the password changed; reviving %v", n-starts, reviving(h, "infra"))
	}
}

// IKEv2: the login had worked, so the reconnected session tries it a few
// times and gives up; the cycle stops there.
func TestFullTunnelRevivalStopsAtARejectedIKEv2Login(t *testing.T) {
	var alive, outside atomic.Bool
	alive.Store(true)
	outside.Store(true)
	h, fi := newIKEHarness(t)
	fi.DNS = []string{"10.30.0.53"} // asked through it: the fake's counters stay at 0
	fastAlive(t, h, &alive, &outside)
	on := true
	spec := domain.TunnelSpec{Name: "eap", Type: domain.TunnelIKEv2, AllTraffic: &on,
		Config: profile("IKEv2", `
        <key>RemoteAddress</key><string>203.0.113.9</string>
        <key>AuthenticationMethod</key><string>None</string>
        <key>ExtendedAuthEnabled</key><true/>
        <key>AuthName</key><string>alice</string>
        <key>AuthPassword</key><string>right</string>`, dataPayload(payloadRoot, "CA-UUID", newTestPKI(t).caDER, ""))}
	if _, err := h.m.Save(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("eap"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "eap", domain.TunnelConnected)

	fi.Fail = []string{"10[IKE] received AUTHENTICATION_FAILED notify error"}
	alive.Store(false)
	st := waitState(t, h.m, "eap", domain.TunnelFailed)
	waitFor(t, "the rejected login given up on", func() bool {
		st, _ = h.m.Status("eap")
		return st.State == domain.TunnelFailed && strings.Contains(st.LastError, "rejected the username or password")
	})
	n := len(fi.Started())
	stillAt(t, func() int { return len(fi.Started()) }, n, 20*h.m.at.first)
	if reviving(h, "eap") {
		t.Fatal("still in its reconnect cycle")
	}
}

// A Disconnect while a reconnect waits ends the cycle: the tunnel isn't
// connected by the timer, and the user's next Connect starts clean.
func TestDisconnectDuringARevive(t *testing.T) {
	var alive, outside atomic.Bool
	alive.Store(true)
	outside.Store(true)
	h := newHarness(t)
	fastAlive(t, h, &alive, &outside)
	h.m.at.first = time.Second // the wait the Disconnect lands in
	if _, err := h.m.Save(context.Background(), fullSpec()); err != nil {
		t.Fatal(err)
	}
	_ = h.m.Connect("infra")
	waitState(t, h.m, "infra", domain.TunnelConnected)
	alive.Store(false)
	waitState(t, h.m, "infra", domain.TunnelFailed)
	if !reviving(h, "infra") {
		t.Fatal("not in a reconnect cycle")
	}
	if err := h.m.Disconnect(t.Context(), "infra"); err != nil {
		t.Fatal(err)
	}
	if reviving(h, "infra") {
		t.Fatal("still reviving after a Disconnect")
	}
	n := h.fl.Starts()
	stillAt(t, h.fl.Starts, n, 3*time.Second/2)

	alive.Store(true)
	_ = h.m.Connect("infra")
	waitState(t, h.m, "infra", domain.TunnelConnected)
	if reviving(h, "infra") {
		t.Fatal("a user's Connect carried the cycle")
	}
}

// A tunnel that comes to list networks while a reconnect waits is still
// the user's to connect: the timer doesn't, and the cycle ends.
func TestReviveSkipsATunnelNoLongerFull(t *testing.T) {
	var alive, outside atomic.Bool
	alive.Store(true)
	outside.Store(true)
	h := newHarness(t)
	fastAlive(t, h, &alive, &outside)
	h.m.at.first = 300 * time.Millisecond
	if _, err := h.m.Save(context.Background(), fullSpec()); err != nil {
		t.Fatal(err)
	}
	_ = h.m.Connect("infra")
	waitState(t, h.m, "infra", domain.TunnelConnected)
	alive.Store(false)
	waitState(t, h.m, "infra", domain.TunnelFailed)
	h.m.mu.Lock()
	d := *h.m.defs["infra"]
	d.AllTraffic = false
	h.m.defs["infra"] = &d
	h.m.mu.Unlock()
	n := h.fl.Starts()
	stillAt(t, h.fl.Starts, n, time.Second)
	if reviving(h, "infra") {
		t.Fatal("still reviving")
	}
}
