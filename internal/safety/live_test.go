package safety_test

import (
	"context"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/safety"
)

// A route RiftRoute installed that another program removes is put back by
// the next apply — through the Apply Protocol, guarded, like any change. One
// removed again and again (a VPN client enforcing its own table) is held
// after the third time: not put back for a while, and reported. Then it's
// tried again. A preview never counts.
func TestLiveRepairPutsBackThenHolds(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	want := desired("9.9.9.0/24")
	apply := func() safety.Result {
		t.Helper()
		res, err := h.p.Apply(ctx, want, nil, opts(false))
		if err != nil {
			t.Fatal(err)
		}
		if res.TxID != "" {
			h.clock.Advance(30 * time.Second) // its guard window
			if result, _ := h.p.Wait(res.TxID); result != domain.TxCommitted {
				t.Fatalf("settled as %s", result)
			}
		}
		return res
	}
	installed := func() bool {
		rs, _ := h.prov.ListRoutes(ctx, domain.FamilyV4)
		for _, r := range rs {
			if r.DstCIDR == "9.9.9.0/24" {
				return true
			}
		}
		return false
	}
	removedByAnother := func() {
		t.Helper()
		if err := h.prov.DelRoute(ctx, want[0]); err != nil {
			t.Fatal(err)
		}
		h.clock.Advance(time.Minute)
	}

	apply()
	for i := 1; i <= 3; i++ {
		removedByAnother()
		if plan, _ := h.p.Plan(ctx, want, nil); len(plan.Ops) != 1 || plan.Ops[0].Kind != domain.OpAddRoute {
			t.Fatalf("removal %d: the preview doesn't put it back: %+v", i, plan.Ops)
		}
		if res := apply(); len(res.Plan.Ops) != 1 || !installed() {
			t.Fatalf("removal %d: not put back (%d ops)", i, len(res.Plan.Ops))
		}
		if held := h.p.HeldRoutes(); (i < 3) != (len(held) == 0) {
			t.Fatalf("removal %d: held %+v", i, held)
		}
	}

	// Held: the fourth removal isn't fought.
	removedByAnother()
	if res := apply(); len(res.Plan.Ops) != 0 || installed() {
		t.Fatalf("a held route was put back (%d ops)", len(res.Plan.Ops))
	}
	held := h.p.HeldRoutes()
	if len(held) != 1 || held[0].Route.DstCIDR != "9.9.9.0/24" || !held[0].Until.After(h.clock.Now()) {
		t.Fatalf("held: %+v", held)
	}

	// The hold over, it's tried again.
	h.clock.Advance(31 * time.Minute)
	if res := apply(); len(res.Plan.Ops) != 1 || !installed() || len(h.p.HeldRoutes()) != 0 {
		t.Fatalf("not tried again after the hold: %d ops, held %+v", len(res.Plan.Ops), h.p.HeldRoutes())
	}
}

// A tunnel's routes are never held — the review's probes for #46: block
// mode's reject route (its networks must never leave another way) and a
// connected tunnel's route into its interface are put back however often
// another program removes them, as before live repair.
func TestLiveRepairNeverHoldsATunnelsRoutes(t *testing.T) {
	for _, r := range []domain.Route{
		{DstCIDR: "10.30.0.0/16", Reject: true, Family: domain.FamilyV4, Owner: domain.OwnerRiftRoute},
		{DstCIDR: "10.30.0.0/16", Iface: "utun8", Family: domain.FamilyV4, Owner: domain.OwnerRiftRoute},
	} {
		h := newHarness(t)
		ctx := context.Background()
		want := []domain.ManagedRoute{{Route: r, ProfileID: "tunnel:office"}}
		o := opts(false)
		o.VetChangesOnly = true // a tunnel's apply
		apply := func() safety.Result {
			t.Helper()
			res, err := h.p.Apply(ctx, want, nil, o)
			if err != nil {
				t.Fatal(err)
			}
			if res.TxID != "" {
				h.clock.Advance(30 * time.Second)
				h.p.Wait(res.TxID)
			}
			return res
		}
		apply()
		for i := 1; i <= 5; i++ {
			if err := h.prov.DelRoute(ctx, want[0]); err != nil {
				t.Fatal(err)
			}
			h.clock.Advance(time.Minute)
			if res := apply(); len(res.Plan.Ops) != 1 {
				t.Fatalf("%+v, removal %d: not put back (%d ops), held %+v", r, i, len(res.Plan.Ops), h.p.HeldRoutes())
			}
		}
		if held := h.p.HeldRoutes(); len(held) != 0 {
			t.Fatalf("%+v: a tunnel's route was held: %+v", r, held)
		}
	}
}

// Another program's route to the same destination: RiftRoute's isn't put
// back beside it (that only meets "File exists", every time) nor counted
// toward a hold, and the other route is left alone. Once it goes, RiftRoute's
// is put back.
func TestLiveRepairLeavesADestinationAnotherRouteHolds(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	want := desired("9.9.9.0/24")
	theirs := domain.ManagedRoute{Route: domain.Route{DstCIDR: "9.9.9.0/24", Iface: "utun3", Family: domain.FamilyV4, Owner: domain.OwnerVPN}}
	apply := func() safety.Result {
		t.Helper()
		res, err := h.p.Apply(ctx, want, nil, opts(false))
		if err != nil {
			t.Fatal(err)
		}
		if res.TxID != "" {
			h.clock.Advance(30 * time.Second)
			h.p.Wait(res.TxID)
		}
		return res
	}
	apply()
	if err := h.prov.DelRoute(ctx, want[0]); err != nil {
		t.Fatal(err)
	}
	if err := h.prov.AddRoute(ctx, theirs); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		h.clock.Advance(time.Minute)
		if res := apply(); len(res.Plan.Ops) != 0 {
			t.Fatalf("tried to put it back beside another route: %+v", res.Plan.Ops)
		}
	}
	if held := h.p.HeldRoutes(); len(held) != 0 {
		t.Fatalf("held: %+v", held)
	}
	rs, _ := h.prov.ListRoutes(ctx, domain.FamilyV4)
	found := false
	for _, r := range rs {
		found = found || r.DstCIDR == "9.9.9.0/24" && r.Iface == "utun3"
	}
	if !found {
		t.Fatal("the other route was touched")
	}
	if err := h.prov.DelRoute(ctx, theirs); err != nil {
		t.Fatal(err)
	}
	if res := apply(); len(res.Plan.Ops) != 1 {
		t.Fatalf("not put back once the other route went: %+v", res.Plan.Ops)
	}
}

// Block mode beside a lower-priority route to the same network (the review's
// case for #46): the tunnel is down, its reject route refuses the network,
// and a fallback with a higher metric sits beside it. When another program
// removes the reject route, it's put back — the fallback doesn't "take" the
// destination, or the tunnel's network would leave by it.
func TestLiveRepairPutsARejectRouteBackBesideAFallback(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	want := []domain.ManagedRoute{{Route: domain.Route{DstCIDR: "10.30.0.0/16", Reject: true, Family: domain.FamilyV4, Owner: domain.OwnerRiftRoute}, ProfileID: "tunnel:office"}}
	fallback := domain.ManagedRoute{Route: domain.Route{DstCIDR: "10.30.0.0/16", Iface: "dum0", Metric: 500, Family: domain.FamilyV4, Owner: domain.OwnerSystem}}
	o := opts(false)
	o.VetChangesOnly = true
	apply := func() safety.Result {
		t.Helper()
		res, err := h.p.Apply(ctx, want, nil, o)
		if err != nil {
			t.Fatal(err)
		}
		if res.TxID != "" {
			h.clock.Advance(30 * time.Second)
			h.p.Wait(res.TxID)
		}
		return res
	}
	if err := h.prov.AddRoute(ctx, fallback); err != nil {
		t.Fatal(err)
	}
	apply()
	for i := 1; i <= 4; i++ {
		if err := h.prov.DelRoute(ctx, want[0]); err != nil {
			t.Fatal(err)
		}
		h.clock.Advance(time.Minute)
		if res := apply(); len(res.Plan.Ops) != 1 || res.Plan.Ops[0].Kind != domain.OpAddRoute {
			t.Fatalf("removal %d: the reject route wasn't put back beside the fallback: %+v", i, res.Plan.Ops)
		}
	}
}
