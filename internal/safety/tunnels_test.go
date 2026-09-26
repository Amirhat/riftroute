package safety_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/safety"
)

// ApplyBuilt hands the build what RiftRoute owns under the apply lock, and a
// build error aborts before anything is touched.
func TestApplyBuiltBuildsFromTheOwnedSet(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.mustApply(t, desired("9.9.9.0/24"))

	var saw []domain.ManagedRoute
	res, err := h.p.ApplyBuilt(ctx, func(owned []domain.ManagedRoute) ([]domain.ManagedRoute, []domain.ManagedRule, error) {
		saw = owned
		return append(owned, desired("8.8.8.0/24")...), nil, nil
	}, opts(false))
	if err != nil || res.Status != domain.TxPending {
		t.Fatalf("apply: %s %v", res.Status, err)
	}
	if len(saw) != 1 || saw[0].DstCIDR != "9.9.9.0/24" {
		t.Fatalf("build saw %+v, want the owned 9.9.9.0/24", saw)
	}
	if h.prov.CountManaged() != 2 {
		t.Fatalf("managed = %d, want 2", h.prov.CountManaged())
	}

	boom := errors.New("boom")
	res, err = h.p.ApplyBuilt(ctx, func([]domain.ManagedRoute) ([]domain.ManagedRoute, []domain.ManagedRule, error) {
		return nil, nil, boom
	}, opts(false))
	if !errors.Is(err, boom) || res.Status != domain.TxFailed || h.prov.CountManaged() != 2 {
		t.Fatalf("a failed build must change nothing: %s %v, managed %d", res.Status, err, h.prov.CountManaged())
	}
}

func onLink(dst, iface, tunnel string) domain.ManagedRoute {
	return domain.ManagedRoute{
		Route:     domain.Route{DstCIDR: dst, Iface: iface, Family: domain.FamilyV4, Owner: domain.OwnerRiftRoute},
		ProfileID: "tunnel:" + tunnel,
	}
}

// A tunnel's routes vanish with its interface. When openvpn re-creates its
// tun under the same name, desired and the ownership map still agree, so a
// diff of the two plans nothing: the apply must check the kernel and put the
// missing routes back — and clear the records of missing ones no longer wanted.
func TestApplyReAddsTunnelRoutesTheKernelDropped(t *testing.T) {
	h := newSimHarness(t)
	ctx := context.Background()
	infra := []domain.ManagedRoute{onLink("192.168.70.0/24", "utun6", "infra"), onLink("192.168.72.0/24", "utun6", "infra")}
	h.applyAndCommit(t, infra, "192.168.1.1")
	h.k.purge(domain.FamilyV4, "", "192.168.70.0/24") // the tun went away…
	h.k.purge(domain.FamilyV4, "", "192.168.72.0/24") // …and came back empty

	h.applyAndCommit(t, infra, "192.168.1.1")
	h.wantRoute(t, "", "192.168.70.0/24", "", "utun6")
	h.wantRoute(t, "", "192.168.72.0/24", "", "utun6")

	// The tunnel drops one route while the kernel already lost it: the
	// stale ownership record goes too.
	h.k.purge(domain.FamilyV4, "", "192.168.72.0/24")
	h.applyAndCommit(t, infra[:1], "192.168.1.1")
	owned, err := h.st.ListOwned()
	if err != nil {
		t.Fatal(err)
	}
	if len(owned) != 1 || owned[0].DstCIDR != "192.168.70.0/24" {
		t.Fatalf("owned = %+v", owned)
	}
	if plan, _ := h.p.Plan(ctx, infra[:1], nil); len(plan.Ops) != 0 {
		t.Fatalf("in sync, but the preview plans %+v", plan.Ops)
	}
}

// VetChangesOnly: a route carried over untouched isn't re-vetted (its next
// hop went stale — now reached through the VPN), but what the apply adds is,
// including a conflict between an added route and a carried one.
func TestVetChangesOnlySkipsRoutesCarriedOver(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	stale := domain.ManagedRoute{Route: domain.Route{DstCIDR: "9.9.9.0/24", Gateway: "10.8.0.77", Iface: "en0", Family: domain.FamilyV4}, ProfileID: "p1"}
	if err := h.prov.AddRoute(ctx, stale); err != nil {
		t.Fatal(err)
	}
	if err := h.st.AddOwned(stale); err != nil {
		t.Fatal(err)
	}
	tunnel := []domain.ManagedRoute{stale, onLink("192.168.70.0/24", "utun9", "infra")}

	o := opts(false)
	if res, err := h.p.Apply(ctx, tunnel, nil, o); !errors.Is(err, safety.ErrGuardrail) {
		t.Fatalf("a full vet refuses the stale route: %s %v", res.Status, err)
	}
	o.VetChangesOnly = true
	if res, err := h.p.Apply(ctx, tunnel, nil, o); err != nil || res.Status != domain.TxPending {
		t.Fatalf("vetting the changes only: %s %v %v", res.Status, err, res.Violations)
	}

	conflict := append(tunnel, domain.ManagedRoute{Route: domain.Route{DstCIDR: "9.9.9.0/24", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4}, ProfileID: "p2"})
	res, err := h.p.Apply(ctx, conflict, nil, o)
	if !errors.Is(err, safety.ErrGuardrail) || len(res.Violations) != 1 || res.Violations[0].Rule != "conflicting-route" {
		t.Fatalf("an added route conflicting with a carried one: %v %+v", err, res.Violations)
	}
}

func pinRoute(dst, tunnel string) domain.ManagedRoute {
	return domain.ManagedRoute{
		Route:     domain.Route{DstCIDR: dst, Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4, Owner: domain.OwnerRiftRoute},
		ProfileID: "tunnel:" + tunnel,
	}
}

// startup is the daemon's crash-recovery order (cmd/riftrouted).
func startup(t *testing.T, h *harness) {
	t.Helper()
	ctx := context.Background()
	if _, err := h.p.RecoverPending(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := h.p.DropTunnelRoutes(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.p.ReconcileOwnership(ctx); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) kernelRoute(t *testing.T, dst string) (domain.Route, bool) {
	t.Helper()
	rs, err := h.prov.ListRoutes(context.Background(), domain.FamilyV4)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.DstCIDR == dst {
			return r, true
		}
	}
	return domain.Route{}, false
}

// After a crash and a reboot, no tunnel is running, and a tunnel's interface
// name (utun5) may now be another VPN's. Startup must not re-add the old
// tunnel's on-link routes by that name, and withdraws its server pin (which
// goes via the physical gateway and outlives the tunnel); profile routes are
// repaired as before.
func TestStartupDropsThePreviousRunsTunnelRoutes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, r := range []domain.ManagedRoute{desired("9.9.9.0/24")[0], onLink("192.168.70.0/24", "utun5", "infra"), pinRoute("198.51.100.7/32", "infra")} {
		if err := h.st.AddOwned(r); err != nil {
			t.Fatal(err)
		}
	}
	// The reboot cleared the kernel, except the pin (say the daemon just
	// crashed); utun5 now belongs to another VPN.
	if err := h.prov.AddRoute(ctx, pinRoute("198.51.100.7/32", "infra")); err != nil {
		t.Fatal(err)
	}
	h.prov.SetTunnelIface("utun5", "10.77.0.2", true)

	startup(t, h)
	if r, ok := h.kernelRoute(t, "192.168.70.0/24"); ok {
		t.Errorf("the old tunnel's route was re-added into the new utun5: %+v", r)
	}
	if r, ok := h.kernelRoute(t, "198.51.100.7/32"); ok {
		t.Errorf("the old tunnel's server pin was left: %+v", r)
	}
	if _, ok := h.kernelRoute(t, "9.9.9.0/24"); !ok {
		t.Error("a profile route wasn't repaired")
	}
	owned, _ := h.st.ListOwned()
	if len(owned) != 1 || owned[0].ProfileID != "p1" {
		t.Errorf("owned = %+v, want only the profile route", owned)
	}
}

// Crash recovery replays an in-flight tunnel withdrawal's inverse: it must not
// re-add the on-link route by interface name either.
func TestRecoverPendingDoesNotReAddTunnelLinks(t *testing.T) {
	h := newHarness(t)
	infra := []domain.ManagedRoute{onLink("192.168.70.0/24", "utun5", "infra"), pinRoute("198.51.100.7/32", "infra")}
	h.prov.SetTunnelIface("utun5", "10.99.0.2", true)
	h.mustApply(t, infra)
	h.clock.Advance(30 * time.Second) // committed
	// The tunnel went down; its withdrawal was in flight when the daemon died.
	h.mustApply(t, nil)
	h.p = safety.NewProtocol(h.prov, h.st, h.clock, func() safety.Prober { return h.prober }, "fake", nil)

	startup(t, h) // (the fake's table survives: a crash without a reboot)
	if r, ok := h.kernelRoute(t, "192.168.70.0/24"); ok {
		t.Errorf("crash recovery re-added the tunnel's on-link route: %+v", r)
	}
	if r, ok := h.kernelRoute(t, "198.51.100.7/32"); ok {
		t.Errorf("the pin crash recovery restored wasn't withdrawn: %+v", r)
	}
	if owned, _ := h.st.ListOwned(); len(owned) != 0 {
		t.Errorf("owned = %+v", owned)
	}
}

// mustApply runs a non-interactive apply that must go through.
func (h *harness) mustApply(t *testing.T, d []domain.ManagedRoute) {
	t.Helper()
	res, err := h.p.Apply(context.Background(), d, nil, opts(false))
	if err != nil || res.Status != domain.TxPending {
		t.Fatalf("apply: %s %v %v", res.Status, err, res.Violations)
	}
}
