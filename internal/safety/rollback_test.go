package safety_test

import (
	"context"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/safety"
)

// An unguarded apply commits as soon as it is applied: no transaction on
// probation, nothing journaled, and no watchdog to roll it back.
func TestUnguardedApplyCommitsAtOnce(t *testing.T) {
	h := newHarness(t)
	o := opts(false)
	o.Unguarded = true
	res, err := h.p.Apply(context.Background(), desired("9.9.9.0/24"), nil, o)
	if err != nil || res.Status != domain.TxCommitted || res.TxID == "" {
		t.Fatalf("apply: %+v %v", res, err)
	}
	if got, ok := h.p.Wait(res.TxID); !ok || got != domain.TxCommitted {
		t.Fatalf("wait: %s %v", got, ok)
	}
	if busy, _ := h.p.Busy(); busy {
		t.Fatal("busy after an unguarded apply")
	}
	if pend, _ := h.st.ListPendingTx(); len(pend) != 0 {
		t.Fatalf("journal = %+v", pend)
	}
	h.prober.SetReachable("192.168.1.1", false)
	h.clock.Advance(time.Minute)
	time.Sleep(20 * time.Millisecond)
	if h.prov.CountManaged() != 1 {
		t.Fatal("an unguarded change was rolled back")
	}
	if owned, _ := h.st.ListOwned(); len(owned) != 1 {
		t.Fatalf("owned = %+v", owned)
	}
}

// fireGuard has the watchdog of the pending tx roll it back.
func (h *harness) fireGuard(t *testing.T, txID string) {
	t.Helper()
	h.prober.SetReachable("192.168.1.1", false)
	h.clock.Advance(time.Second) // K=1
	if got, _ := h.p.Wait(txID); got != domain.TxRolledBack {
		t.Fatalf("want rolled back, got %s", got)
	}
	h.prober.SetReachable("192.168.1.1", true)
}

// A guarded apply that withdrew a tunnel's routes, rolled back after the
// tunnel went away: its on-link route isn't re-added — the interface is gone
// (or another VPN's) — and the pin it does re-add is recorded, so it isn't
// left in the kernel unowned. Nothing failed, so nothing stays journaled.
func TestRollbackSkipsTunnelLinksAndRecordsWhatItRestores(t *testing.T) {
	h := newHarness(t)
	h.prov.SetTunnelIface("utun5", "10.99.0.2", true)
	h.mustApply(t, []domain.ManagedRoute{onLink("192.168.70.0/24", "utun5", "infra"), pinRoute("198.51.100.7/32", "infra")})
	h.clock.Advance(30 * time.Second) // committed

	res, err := h.p.Apply(context.Background(), nil, nil, opts(false))
	if err != nil || res.Status != domain.TxPending {
		t.Fatalf("withdrawal: %s %v", res.Status, err)
	}
	h.prov.SetTunnelIface("utun5", "", false)
	h.prov.FailAddRoute("192.168.70.0/24", true) // no utun5 to re-add it into
	h.fireGuard(t, res.TxID)

	if r, ok := h.kernelRoute(t, "192.168.70.0/24"); ok {
		t.Errorf("the on-link route was re-added: %+v", r)
	}
	if _, ok := h.kernelRoute(t, "198.51.100.7/32"); !ok {
		t.Error("the pin wasn't restored")
	}
	owned, _ := h.st.ListOwned()
	if len(owned) != 1 || owned[0].DstCIDR != "198.51.100.7/32" {
		t.Errorf("owned = %+v, want the restored pin only", owned)
	}
	if pend, _ := h.st.ListPendingTx(); len(pend) != 0 {
		t.Errorf("journal = %+v, want empty", pend)
	}
}

// A rollback that fails part-way records what it did restore, and keeps
// only what it didn't journaled — which crash recovery then finishes.
func TestIncompleteRollbackRecordsWhatWentThrough(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.mustApply(t, desired("9.9.9.0/24", "8.8.8.0/24"))
	h.clock.Advance(30 * time.Second) // committed

	res, err := h.p.Apply(ctx, nil, nil, opts(false))
	if err != nil || res.Status != domain.TxPending {
		t.Fatalf("withdrawal: %s %v", res.Status, err)
	}
	h.prov.FailAddRoute("8.8.8.0/24", true)
	h.fireGuard(t, res.TxID)

	owned, _ := h.st.ListOwned()
	if len(owned) != 1 || owned[0].DstCIDR != "9.9.9.0/24" {
		t.Fatalf("owned = %+v, want the restored 9.9.9.0/24 only", owned)
	}
	if h.prov.CountManaged() != 1 {
		t.Fatalf("managed = %d", h.prov.CountManaged())
	}
	pend, _ := h.st.ListPendingTx()
	left, ok := pend[res.TxID]
	if len(pend) != 1 || !ok || len(left.Inverse) != 1 || left.Inverse[0].Kind != domain.OpAddRoute || left.Inverse[0].Route.DstCIDR != "8.8.8.0/24" ||
		len(left.Ops) != 1 || left.Ops[0].Kind != domain.OpDelRoute {
		t.Fatalf("journal = %+v, want only the failed re-add of 8.8.8.0/24", pend)
	}

	h.prov.FailAddRoute("8.8.8.0/24", false)
	p2 := safety.NewProtocol(h.prov, h.st, h.clock, func() safety.Prober { return h.prober }, "fake", nil)
	if n, err := p2.RecoverPending(ctx); err != nil || n != 1 {
		t.Fatalf("recover: %d %v", n, err)
	}
	if owned, _ := h.st.ListOwned(); len(owned) != 2 || h.prov.CountManaged() != 2 {
		t.Fatalf("after recovery: owned %+v, managed %d", owned, h.prov.CountManaged())
	}
}
