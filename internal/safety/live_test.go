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
