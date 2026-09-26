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
	prov      *fake.Provider
	st        *store.Store
	svc       *core.Service
	proto     *safety.Protocol
	rec       *reconcile.Reconciler
	autoApply atomic.Bool

	mu     sync.Mutex
	inputs []routing.TunnelInput
}

func newTunnelHarness(t *testing.T) *tunnelHarness {
	t.Helper()
	h := &tunnelHarness{prov: fake.New()}
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
