package safety_test

import (
	"context"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/safety"
)

// The updater waits for Busy to clear: a change awaiting confirmation keeps
// the daemon busy; once it's confirmed it isn't, and the last change's time
// is reported.
func TestBusyWhileAChangeAwaitsConfirmation(t *testing.T) {
	h := newHarness(t)
	if busy, last := h.p.Busy(); busy || !last.IsZero() {
		t.Fatalf("fresh protocol: busy=%v last=%v", busy, last)
	}
	res, err := h.p.Apply(context.Background(), desired("1.1.1.0/24"), nil, opts(true))
	if err != nil {
		t.Fatal(err)
	}
	if busy, last := h.p.Busy(); !busy || last.IsZero() {
		t.Fatalf("awaiting confirmation: busy=%v last=%v", busy, last)
	}
	if _, err := h.p.Confirm(res.TxID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if busy, _ := h.p.Busy(); !busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("still busy after the change was confirmed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TryQuiesce refuses while a change awaits confirmation, and once taken it
// blocks new changes until released.
func TestTryQuiesceHoldsOffNewChanges(t *testing.T) {
	h := newHarness(t)
	res, err := h.p.Apply(context.Background(), desired("1.1.1.0/24"), nil, opts(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, why := h.p.TryQuiesce(0); ok || why == "" {
		t.Fatal("quiesced while a change awaits confirmation")
	}
	if _, err := h.p.Confirm(res.TxID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	var release func()
	for {
		var ok bool
		if release, ok, _ = h.p.TryQuiesce(0); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("never quiet after confirming")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok, _ := h.p.TryQuiesce(time.Hour); ok {
		t.Fatal("a recent change should keep it from being quiet for an hour")
	}
	done := make(chan struct{})
	go func() {
		_, _ = h.p.Apply(context.Background(), desired("2.2.2.0/24"), nil, opts(false))
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("a change went through while quiesced")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	release() // idempotent
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the change never ran after release")
	}
}

// A restarting updater keeps the apply lock until the process exits, and
// lends it to the tunnels' last applies (LendQuiesce): a Lendable apply goes
// through then — not before — while any other change still waits. Released,
// nothing is lent any more; without a quiesce, lending does nothing.
func TestLendQuiesceLetsOnlyTunnelAppliesThrough(t *testing.T) {
	h := newHarness(t)
	reject := domain.ManagedRoute{Route: domain.Route{DstCIDR: "9.9.9.9/32", Family: domain.FamilyV4, Reject: true}, ProfileID: "tunnel:con3"}
	build := func(rs ...domain.ManagedRoute) safety.Build {
		return func(context.Context, []domain.ManagedRoute, *safety.Options) ([]domain.ManagedRoute, []domain.ManagedRule, error) {
			return rs, nil, nil
		}
	}
	tunnelOpts := opts(false)
	tunnelOpts.Unguarded, tunnelOpts.VetChangesOnly, tunnelOpts.Lendable = true, true, true
	short := func() context.Context {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		t.Cleanup(cancel)
		return ctx
	}

	h.p.LendQuiesce() // not quiesced: nothing to lend
	release, ok, why := h.p.TryQuiesce(0)
	if !ok {
		t.Fatal(why)
	}
	if _, err := h.p.ApplyBuilt(short(), build(reject), tunnelOpts); err == nil {
		t.Fatal("a tunnel apply went through before the lock was lent")
	}
	h.p.LendQuiesce()
	if res, err := h.p.ApplyBuilt(short(), build(reject), tunnelOpts); err != nil || res.Status != domain.TxCommitted {
		t.Fatalf("the lent tunnel apply: %v %s", err, res.Status)
	}
	if owned, _ := h.st.ListOwned(); len(owned) != 1 || !owned[0].Reject {
		t.Fatalf("owned = %+v", owned)
	}
	if _, err := h.p.ApplyBuilt(short(), build(desired("10.0.0.0/8")...), opts(false)); err == nil {
		t.Fatal("a non-tunnel apply went through the lent lock")
	}
	release()
	if res, err := h.p.ApplyBuilt(short(), build(), tunnelOpts); err != nil || res.Status != domain.TxCommitted {
		t.Fatalf("after the release: %v %s", err, res.Status)
	}
	if _, ok, _ := h.p.TryQuiesce(0); ok {
		// Taking it again is fine; it must not come lent.
		if _, err := h.p.ApplyBuilt(short(), build(reject), tunnelOpts); err == nil {
			t.Fatal("a new quiesce came lent")
		}
	}
}
