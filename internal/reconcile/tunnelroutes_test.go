package reconcile_test

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/reconcile"
	"github.com/Amirhat/riftroute/internal/routing"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/store"
)

// tunnelHarness drives the reconciler with fixed tunnel inputs — what the
// tunnel manager's Inputs would report — over the fake provider.
type tunnelHarness struct {
	prov      *hookProvider
	st        *store.Store
	svc       *core.Service
	proto     *safety.Protocol
	rec       *reconcile.Reconciler
	autoApply atomic.Bool

	mu     sync.Mutex
	inputs []routing.TunnelInput
}

// hookProvider is the fake provider with one-shot hooks on its reads, so a
// test can land a change in the middle of another apply.
type hookProvider struct {
	*fake.Provider
	mu                sync.Mutex
	onRules, onIfaces func()
}

func (p *hookProvider) take(fn *func()) func() {
	p.mu.Lock()
	defer p.mu.Unlock()
	f := *fn
	*fn = nil
	return f
}

func (p *hookProvider) ListRules(ctx context.Context, fam domain.Family) ([]domain.PolicyRule, error) {
	if f := p.take(&p.onRules); f != nil {
		f()
	}
	return p.Provider.ListRules(ctx, fam)
}

func (p *hookProvider) Interfaces(ctx context.Context) ([]domain.Iface, error) {
	if f := p.take(&p.onIfaces); f != nil {
		f()
	}
	return p.Provider.Interfaces(ctx)
}

func (p *hookProvider) hook(at *func(), fn func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	*at = fn
}

// landing runs change concurrently and waits for it to finish — or to be
// held back by the apply lock, which is what a correct apply does to it.
func landing(change func()) (hook func(), wait func()) {
	done := make(chan struct{})
	return func() {
			go func() { defer close(done); change() }()
			select {
			case <-done:
			case <-time.After(300 * time.Millisecond):
			}
		}, func() {
			<-done
		}
}

func newTunnelHarness(t *testing.T) *tunnelHarness {
	t.Helper()
	h := &tunnelHarness{prov: &hookProvider{Provider: fake.New()}}
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	h.st = st
	h.svc = core.New(h.prov, st, "test")
	h.proto = safety.NewProtocol(h.prov, st, safety.NewFakeClock(time.Unix(0, 0)), func() safety.Prober { return safety.NewFakeProber() }, "fake", nil)
	t.Cleanup(h.proto.ShutdownResolve)
	h.rec = reconcile.New(h.svc, h.proto, slog.New(slog.NewTextHandler(io.Discard, nil)), 0, h.autoApply.Load)
	h.svc.SetTunnels(func() []routing.TunnelInput {
		h.mu.Lock()
		defer h.mu.Unlock()
		return append([]routing.TunnelInput(nil), h.inputs...)
	}, func() []domain.TunnelStatus { return nil })
	return h
}

// setTunnels replaces the running tunnels, bringing up (in the fake) the
// interface each live one is on.
func (h *tunnelHarness) setTunnels(ins ...routing.TunnelInput) {
	for _, in := range ins {
		if in.Iface != "" {
			h.prov.SetTunnelIface(in.Iface, "10.99.0.2", true)
		}
	}
	h.mu.Lock()
	h.inputs = ins
	h.mu.Unlock()
}

// own records r as installed and owned — what an earlier apply left.
func (h *tunnelHarness) own(t *testing.T, r domain.ManagedRoute) {
	t.Helper()
	if err := h.prov.AddRoute(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if err := h.st.AddOwned(r); err != nil {
		t.Fatal(err)
	}
}

// kernel maps each installed destination to the interfaces routing it.
func (h *tunnelHarness) kernel(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, fam := range []domain.Family{domain.FamilyV4, domain.FamilyV6} {
		rs, err := h.prov.ListRoutes(context.Background(), fam)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rs {
			out[r.DstCIDR] = append(out[r.DstCIDR], r.Iface)
		}
	}
	return out
}

func excludeRoute(dst string) domain.ManagedRoute {
	return domain.ManagedRoute{Route: domain.Route{DstCIDR: dst, Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4}, ProfileID: "p1"}
}

// An applied exclude route for exactly a tunnel's destination: the tunnel
// wins inside its networks (as it does in a full reconcile), instead of the
// tunnel apply being refused over a destination with two next hops.
func TestTunnelApplyTakesOverAnAppliedExcludeRoute(t *testing.T) {
	h := newTunnelHarness(t)
	h.own(t, excludeRoute("192.168.70.0/24"))
	h.own(t, excludeRoute("9.9.9.0/24"))
	h.setTunnels(routing.TunnelInput{Name: "infra", Iface: "utun9", Routes: []string{"192.168.70.0/24"}})

	if err := h.rec.ApplyTunnels(context.Background()); err != nil {
		t.Fatalf("tunnel apply refused: %v", err)
	}
	k := h.kernel(t)
	if got := k["192.168.70.0/24"]; len(got) != 1 || got[0] != "utun9" {
		t.Errorf("192.168.70.0/24 via %v, want only utun9", got)
	}
	if got := k["9.9.9.0/24"]; len(got) != 1 || got[0] != "en0" {
		t.Errorf("an unrelated exclude route changed: %v", got)
	}
}

// openvpn re-creates its tun under the same name (a reconnect): the kernel
// dropped the tunnel's routes with the old one. The next tunnel apply (the
// manager applies on CONNECTED) and a network-event reconcile must both put
// them back.
func TestTunnelRoutesComeBackAfterTheTunIsRecreated(t *testing.T) {
	h := newTunnelHarness(t)
	h.setTunnels(routing.TunnelInput{Name: "infra", Iface: "utun9", Routes: []string{"192.168.70.0/24"}})
	ctx := context.Background()
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}

	h.prov.PurgeIface("utun9")
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.kernel(t)["192.168.70.0/24"]; len(got) != 1 || got[0] != "utun9" {
		t.Fatalf("tunnel apply: route = %v, want it back on utun9", got)
	}

	h.prov.PurgeIface("utun9")
	h.autoApply.Store(true)
	if _, err := h.rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.kernel(t)["192.168.70.0/24"]; len(got) != 1 || got[0] != "utun9" {
		t.Fatalf("reconcile: route = %v, want it back on utun9", got)
	}
}

// A network move with auto-apply off: the exclude routes applied earlier stay
// as they were (staged changes are the user's to apply), now with a stale
// next hop the VPN routes. The tunnel must still follow the move — its pin is
// part of it — and still be able to go down: the guardrails vet what the
// tunnel apply changes, not the stale routes it carries over untouched.
func TestNetworkMoveRePinsTunnelsWithAutoApplyOff(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	h.own(t, excludeRoute("9.9.9.0/24"))
	infra := routing.TunnelInput{Name: "infra", Iface: "utun9", Routes: []string{"192.168.70.0/24"}, Bypass: []netip.Addr{netip.MustParseAddr("198.51.100.7")}}
	h.setTunnels(infra)
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}

	// Wi-Fi → Ethernet: the old LAN (and every route through it) is gone,
	// so 192.168.1.1 is now reached through the VPN.
	h.prov.PurgeIface("en0")
	if err := h.prov.AddRoute(ctx, domain.ManagedRoute{Route: domain.Route{DstCIDR: "10.0.0.0/24", Iface: "en7", Family: domain.FamilyV4}}); err != nil {
		t.Fatal(err)
	}
	h.prov.SetPhysGateway(domain.FamilyV4, netip.MustParseAddr("10.0.0.1"), "en7")

	if _, err := h.rec.Reconcile(ctx); err != nil { // the network event
		t.Fatalf("network-change reconcile: %v", err)
	}
	rs, _ := h.prov.ListRoutes(ctx, domain.FamilyV4)
	pinned := false
	for _, r := range rs {
		if r.DstCIDR == "198.51.100.7/32" {
			pinned = r.Gateway == "10.0.0.1" && r.Iface == "en7"
		}
	}
	if !pinned {
		t.Fatalf("the server pin didn't follow the move: %v", h.kernel(t))
	}
	owned, _ := h.st.ListOwned()
	for _, o := range owned {
		if o.DstCIDR == "9.9.9.0/24" && o.Gateway != "192.168.1.1" {
			t.Errorf("a staged exclude route was re-applied with auto-apply off: %+v", o)
		}
	}

	h.setTunnels() // disconnect
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatalf("withdrawal refused: %v", err)
	}
	for _, o := range h.ownedTunnelRoutes(t) {
		t.Errorf("left behind: %+v", o)
	}
}

// A previous run's tunnel withdrawal was refused at shutdown (an interactive
// change awaited confirmation), leaving its routes. Startup — the drop, then
// the tunnels' resync (the manager's Resync applies through ApplyTunnels) —
// must leave nothing behind, even when the pin won't delete at first.
func TestStartupCleansALeftoverTunnel(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	infra := routing.TunnelInput{Name: "infra", Iface: "utun9", Routes: []string{"192.168.70.0/24"}, Bypass: []netip.Addr{netip.MustParseAddr("198.51.100.7")}}
	h.setTunnels(infra)
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	h.proto.ShutdownResolve()

	// Restart: openvpn is gone (with utun9's routes), the pin is not.
	h.prov.SetTunnelIface("utun9", "", false)
	h.prov.PurgeIface("utun9")
	h.setTunnels()
	h.proto = safety.NewProtocol(h.prov, h.st, safety.NewFakeClock(time.Unix(0, 0)), func() safety.Prober { return safety.NewFakeProber() }, "fake", nil)
	h.rec = reconcile.New(h.svc, h.proto, slog.New(slog.NewTextHandler(io.Discard, nil)), 0, h.autoApply.Load)

	h.prov.FailDelRoute("198.51.100.7/32", true) // the pin won't delete yet
	if _, err := h.proto.RecoverPending(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := h.proto.DropTunnelRoutes(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.proto.ReconcileOwnership(ctx); err != nil {
		t.Fatal(err)
	}
	if !h.svc.OwnsTunnelRoutes(ctx) {
		t.Fatal("the pin that wouldn't delete must stay recorded, for the resync")
	}
	if got := h.kernel(t)["192.168.70.0/24"]; len(got) != 0 {
		t.Fatalf("startup re-added the old tunnel's route by interface name: %v", got)
	}
	h.prov.FailDelRoute("198.51.100.7/32", false)
	if err := h.rec.ApplyTunnels(ctx); err != nil { // tunnels.Resync
		t.Fatal(err)
	}
	for _, o := range h.ownedTunnelRoutes(t) {
		t.Errorf("still recorded: %+v", o)
	}
	k := h.kernel(t)
	for _, dst := range []string{"192.168.70.0/24", "198.51.100.7/32"} {
		if len(k[dst]) != 0 {
			t.Errorf("%s left in the kernel via %v", dst, k[dst])
		}
	}
}

func (h *tunnelHarness) ownedTunnelRoutes(t *testing.T) []domain.ManagedRoute {
	t.Helper()
	owned, err := h.st.ListOwned()
	if err != nil {
		t.Fatal(err)
	}
	var out []domain.ManagedRoute
	for _, o := range owned {
		if strings.HasPrefix(o.ProfileID, routing.TunnelProfilePrefix) {
			out = append(out, o)
		}
	}
	return out
}

func directProfile(t *testing.T, st *store.Store, cidr string) {
	t.Helper()
	if err := st.UpsertProfile(domain.Profile{
		ID: "p1", Name: "direct", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: cidr}},
	}); err != nil {
		t.Fatal(err)
	}
}

// An auto-apply landing while a tunnel apply reads what RiftRoute owns must
// not be undone by it: the tunnel apply derives its desired set under the
// apply lock.
func TestTunnelApplyDoesNotUndoAConcurrentAutoApply(t *testing.T) {
	h := newTunnelHarness(t)
	h.autoApply.Store(true)
	directProfile(t, h.st, "9.9.9.0/24")
	h.setTunnels(routing.TunnelInput{Name: "infra", Iface: "utun9", Routes: []string{"192.168.70.0/24"}})
	ctx := context.Background()

	hook, wait := landing(func() { _, _ = h.rec.Reconcile(ctx) })
	h.prov.hook(&h.prov.onRules, hook)
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	wait()
	k := h.kernel(t)
	if len(k["9.9.9.0/24"]) != 1 {
		t.Errorf("the tunnel apply undid the auto-apply that landed during it: %v", k)
	}
	if got := k["192.168.70.0/24"]; len(got) != 1 || got[0] != "utun9" {
		t.Errorf("tunnel route = %v", got)
	}
}

// …and the reverse: a tunnel apply landing while an auto-apply derives its
// desired set must not be undone by it.
func TestAutoApplyDoesNotUndoAConcurrentTunnelApply(t *testing.T) {
	h := newTunnelHarness(t)
	h.autoApply.Store(true)
	directProfile(t, h.st, "9.9.9.0/24")
	h.setTunnels(routing.TunnelInput{Name: "infra", Routes: []string{"192.168.70.0/24"}}) // connecting
	ctx := context.Background()

	hook, wait := landing(func() {
		h.setTunnels(routing.TunnelInput{Name: "infra", Iface: "utun9", Routes: []string{"192.168.70.0/24"}}) // connected
		_ = h.rec.ApplyTunnels(ctx)
	})
	h.prov.hook(&h.prov.onIfaces, hook)
	if _, err := h.rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	wait()
	k := h.kernel(t)
	if got := k["192.168.70.0/24"]; len(got) != 1 || got[0] != "utun9" {
		t.Errorf("the auto-apply undid the tunnel apply that landed during it: %v", k)
	}
	if len(k["9.9.9.0/24"]) != 1 {
		t.Errorf("profile route = %v", k["9.9.9.0/24"])
	}
}
