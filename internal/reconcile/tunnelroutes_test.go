package reconcile_test

import (
	"context"
	"io"
	"log/slog"
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
