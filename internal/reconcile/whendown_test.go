package reconcile_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/reconcile"
	"github.com/Amirhat/riftroute/internal/routing"
	"github.com/Amirhat/riftroute/internal/safety"
)

// refused lists the destinations the (fake) kernel holds reject routes for.
func (h *tunnelHarness) refused(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, fam := range []domain.Family{domain.FamilyV4, domain.FamilyV6} {
		rs, err := h.prov.ListRoutes(context.Background(), fam)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rs {
			if r.Reject {
				out[r.DstCIDR] = true
			}
		}
	}
	return out
}

var (
	con3Blocked = routing.TunnelInput{Name: "con3", Block: true, Routes: []string{"9.9.9.9/32"}}
	con3Live    = routing.TunnelInput{Name: "con3", Iface: "utun8", Block: true, Routes: []string{"9.9.9.9/32"}}
)

// A block-mode tunnel that's down refuses its destinations — its own routes
// and its profiles' — through the Apply Protocol; once it's up they go into
// it, and nothing refuses them; down again, they're refused again; once it's
// no longer wanted, nothing is left.
func TestBlockedTunnelRefusesThenRoutesItsDestinations(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	h.tunnelProfile(t, true, "10.20.0.0/24")
	h.setTunnels(con3Blocked)
	h.fullApply(t)
	if r := h.refused(t); !r["9.9.9.9/32"] || !r["10.20.0.0/24"] || len(r) != 2 {
		t.Fatalf("refused = %v", r)
	}

	h.setTunnels(con3Live)
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	k := h.kernel(t)
	for _, dst := range []string{"9.9.9.9/32", "10.20.0.0/24"} {
		if got := k[dst]; len(got) != 1 || got[0] != "utun8" {
			t.Errorf("%s = %v, want into utun8 alone", dst, got)
		}
	}
	if r := h.refused(t); len(r) != 0 {
		t.Errorf("still refused while it's up: %v", r)
	}

	h.setTunnels(con3Blocked) // it dropped
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	if r := h.refused(t); !r["9.9.9.9/32"] || !r["10.20.0.0/24"] {
		t.Fatalf("after the drop, refused = %v", r)
	}

	h.setTunnels() // disconnected by the user
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	if k := h.kernel(t); len(k["9.9.9.9/32"]) != 0 || len(k["10.20.0.0/24"]) != 0 {
		t.Errorf("left behind: %v %v", k["9.9.9.9/32"], k["10.20.0.0/24"])
	}
}

// An exclude route inside a blocked tunnel's network yields — it would carry
// the traffic out past the block — and comes back when the block lifts.
func TestExcludeRouteYieldsToTheBlockAndComesBack(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	h.profileP1(t, true) // 10.70.9.0/24 inside the tunnel's network, 10.80.0.0/24 outside
	h.setTunnels(routing.TunnelInput{Name: "infra", Block: true, Routes: []string{"10.70.0.0/16"}})
	h.fullApply(t)
	k := h.kernel(t)
	if len(k["10.70.9.0/24"]) != 0 || !h.refused(t)["10.70.0.0/16"] || len(k["10.80.0.0/24"]) != 1 {
		t.Fatalf("kernel = %v", k)
	}

	h.setTunnels()
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.kernel(t)["10.70.9.0/24"]; len(got) != 1 || got[0] != "en0" {
		t.Errorf("the yielded route after the block = %v, want it back via en0", got)
	}
	if h.refused(t)["10.70.0.0/16"] {
		t.Error("the block stayed")
	}
}

// The route lookup says a blocked destination is refused by its tunnel —
// now, and as desired — rather than unreachable.
func TestExplainNamesTheBlockingTunnel(t *testing.T) {
	h := newTunnelHarness(t)
	h.setTunnels(con3Blocked)
	if err := h.rec.ApplyTunnels(context.Background()); err != nil {
		t.Fatal(err)
	}
	ex, err := h.svc.Explain(context.Background(), "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []domain.RouteDecision{ex.Kernel, *ex.Simulated} {
		if !d.Rejected || d.Reachable || d.Tunnel != "con3" {
			t.Errorf("%s decision = %+v", d.Source, d)
		}
	}
	if ex.Drift {
		t.Error("drift while both refuse it")
	}
}

// A panic flushes the reject routes with everything else.
func TestPanicFlushesTheBlock(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	h.setTunnels(con3Blocked)
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	h.setTunnels() // the panic takes the tunnels down first (no longer wanted)
	if err := h.proto.PanicWith(ctx, domain.ActorUI, safety.PanicSteps{Flushing: h.svc.ForgetRecords}); err != nil {
		t.Fatal(err)
	}
	if r := h.refused(t); len(r) != 0 {
		t.Errorf("refused after the panic: %v", r)
	}
}

// restartAfterCrash starts a new Protocol over the same kernel and store —
// the daemon back after a crash, with no tunnel running — and runs the
// startup recovery (cmd/riftrouted's order).
func (h *tunnelHarness) restartAfterCrash(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	h.setTunnels()
	h.proto = safety.NewProtocol(h.prov, h.st, safety.NewFakeClock(time.Unix(0, 0)), func() safety.Prober { return safety.NewFakeProber() }, "fake", nil)
	h.rec = reconcile.New(h.svc, h.proto, slog.New(slog.NewTextHandler(io.Discard, nil)), 0, h.autoApply.Load)
	if _, err := h.proto.RecoverPending(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := h.proto.DropTunnelRoutes(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.proto.ReconcileOwnership(ctx); err != nil {
		t.Fatal(err)
	}
}

// After a crash, a block-mode tunnel's reject route stays — recorded, so
// the tunnels' startup resync runs and decides: kept for a tunnel that's
// wanted again (the block holds across the restart), withdrawn for one
// that isn't. On macOS the table tags nothing as RiftRoute's; forgetting
// the record would leave the route owned by nothing, past a panic.
func TestRejectRoutesOutliveACrashForTheResyncToDecide(t *testing.T) {
	for _, wanted := range []bool{true, false} {
		t.Run(map[bool]string{true: "wanted again", false: "not wanted"}[wanted], func(t *testing.T) {
			h := newTunnelHarness(t)
			ctx := context.Background()
			h.prov.untagged = true
			h.setTunnels(con3Blocked)
			if err := h.rec.ApplyTunnels(ctx); err != nil {
				t.Fatal(err)
			}

			h.restartAfterCrash(t)
			if !h.refused(t)["9.9.9.9/32"] || !h.svc.OwnsTunnelRoutes(ctx) {
				t.Fatalf("startup dropped the block: refused %v, recorded %v", h.refused(t), h.ownedTunnelRoutes(t))
			}

			if wanted {
				h.setTunnels(con3Blocked)
			}
			if err := h.rec.ApplyTunnels(ctx); err != nil { // tunnels.Resync
				t.Fatal(err)
			}
			if got := h.refused(t)["9.9.9.9/32"]; got != wanted {
				t.Fatalf("refused after the resync = %v, want %v", got, wanted)
			}
			if !wanted && len(h.ownedTunnelRoutes(t)) != 0 {
				t.Errorf("still recorded: %+v", h.ownedTunnelRoutes(t))
			}
		})
	}
}

// ...and a panic right after that startup still removes it.
func TestPanicAfterACrashRemovesTheBlock(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	h.prov.untagged = true
	h.setTunnels(con3Blocked)
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	h.restartAfterCrash(t)
	if err := h.proto.PanicWith(ctx, domain.ActorUI, safety.PanicSteps{Flushing: h.svc.ForgetRecords}); err != nil {
		t.Fatal(err)
	}
	if r := h.refused(t); len(r) != 0 {
		t.Errorf("refused after the panic: %v", r)
	}
}
