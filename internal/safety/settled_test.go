package safety_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/safety"
)

// The settled hook fires each time a transaction on probation resolves, and
// after a panic has flushed — the moments a refused tunnel apply can go
// through, or a rollback may have taken the tunnels' routes.
func TestOnSettledFiresWhenATransactionResolves(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	fired := make(chan struct{}, 16)
	h.p.SetOnSettled(func() { fired <- struct{}{} })
	expect := func(n int, after string) {
		t.Helper()
		for range n {
			select {
			case <-fired:
			case <-time.After(2 * time.Second):
				t.Fatalf("not called after %s", after)
			}
		}
		select {
		case <-fired:
			t.Fatalf("called once too often after %s", after)
		case <-time.After(30 * time.Millisecond):
		}
	}

	res, _ := h.p.Apply(ctx, desired("9.9.9.0/24"), nil, opts(false))
	expect(0, "an apply still on probation")
	h.clock.Advance(30 * time.Second)
	h.p.Wait(res.TxID)
	expect(1, "its guard window committed it")

	res, _ = h.p.Apply(ctx, desired("8.8.8.0/24"), nil, opts(false))
	h.fireGuard(t, res.TxID)
	expect(1, "a watchdog rolled it back")

	res, _ = h.p.Apply(ctx, desired("8.8.8.0/24"), nil, opts(true))
	if _, err := h.p.Confirm(res.TxID); err != nil {
		t.Fatal(err)
	}
	expect(1, "a confirmation")

	res, _ = h.p.Apply(ctx, desired("7.7.7.0/24"), nil, opts(true))
	if _, err := h.p.Rollback(res.TxID); err != nil {
		t.Fatal(err)
	}
	expect(1, "a rollback by hand")

	o := opts(false)
	o.Unguarded = true
	if _, err := h.p.Apply(ctx, desired("9.9.9.0/24", "6.6.6.0/24"), nil, o); err != nil {
		t.Fatal(err)
	}
	expect(0, "an unguarded apply that nobody waited on")

	h.mustApply(t, desired("9.9.9.0/24"))
	if err := h.p.Panic(ctx, domain.ActorUI); err != nil {
		t.Fatal(err)
	}
	expect(2, "a panic settled a guard, then flushed")
}

// The hook runs outside the protocol's locks, so it can apply — even when
// the transaction was settled by a newer apply holding the apply lock.
func TestOnSettledCanApply(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.mustApply(t, desired("9.9.9.0/24"))
	reapplied := make(chan error, 1)
	var once sync.Once
	h.p.SetOnSettled(func() {
		once.Do(func() {
			o := opts(false)
			o.Unguarded = true
			_, err := h.p.ApplyBuilt(ctx, func(_ context.Context, owned []domain.ManagedRoute, _ *safety.Options) ([]domain.ManagedRoute, []domain.ManagedRule, error) {
				return append(owned, desired("7.7.7.0/24")...), nil, nil
			}, o)
			reapplied <- err
		})
	})
	h.mustApply(t, desired("9.9.9.0/24", "8.8.8.0/24")) // settles the first
	select {
	case err := <-reapplied:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the hook's apply never went through")
	}
	if n := h.prov.CountManaged(); n != 3 {
		t.Fatalf("managed = %d, want 3", n)
	}
}
