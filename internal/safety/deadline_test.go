package safety_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/safety"
)

// ctxProvider is the fake provider with route ops that fail once their
// context is done, as route(8)/ip under exec.CommandContext do. The first
// add runs deadline, if set — the apply's deadline passing mid-execution.
type ctxProvider struct {
	*fake.Provider
	mu       sync.Mutex
	deadline func()
}

func (p *ctxProvider) AddRoute(ctx context.Context, mr domain.ManagedRoute) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.Provider.AddRoute(ctx, mr); err != nil {
		return err
	}
	p.mu.Lock()
	fire := p.deadline
	p.deadline = nil
	p.mu.Unlock()
	if fire != nil {
		fire()
	}
	return nil
}

func (p *ctxProvider) DelRoute(ctx context.Context, mr domain.ManagedRoute) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return p.Provider.DelRoute(ctx, mr)
}

// The apply's deadline passing mid-execution must not cut it off: an op
// failing on the expired context, then a rollback failing on it too, would
// leave the first route in the kernel with no record of it.
func TestApplyOutlivesItsDeadlineMidExecution(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prov := &ctxProvider{Provider: h.prov, deadline: cancel}
	p := safety.NewProtocol(prov, h.st, h.clock, func() safety.Prober { return h.prober }, "fake", slog.New(slog.NewTextHandler(io.Discard, nil)))

	res, err := p.Apply(ctx, desired("9.9.9.0/24", "8.8.8.0/24"), nil, opts(false))
	if err != nil || res.Status != domain.TxPending {
		t.Fatalf("apply: %s %v %s", res.Status, err, res.Error)
	}
	if n := h.prov.CountManaged(); n != 2 {
		t.Fatalf("%d managed route(s), want both", n)
	}
	if owned, _ := h.st.ListOwned(); len(owned) != 2 {
		t.Fatalf("owned = %+v, want both", owned)
	}
}

// The executor's rollback runs to the end even when its context is done.
func TestExecutorRollsBackOnAnExpiredContext(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prov := &ctxProvider{Provider: h.prov, deadline: cancel}
	h.prov.FailAddRoute("8.8.8.0/24", true)
	plan := domain.Plan{Ops: []domain.PlanOp{
		{Kind: domain.OpAddRoute, Route: &desired("9.9.9.0/24")[0]},
		{Kind: domain.OpAddRoute, Route: &desired("8.8.8.0/24")[0]},
	}}
	if err := safety.NewExecutor(prov).Apply(ctx, plan); err == nil {
		t.Fatal("the failing op went through")
	}
	if n := h.prov.CountManaged(); n != 0 {
		t.Fatalf("the rollback left %d route(s)", n)
	}
}

// An apply stuck behind another change gives up when its caller's context
// ends — and doesn't take the lock and make its change afterwards.
func TestApplyGivesUpWaitingForTheLock(t *testing.T) {
	h := newHarness(t)
	release, ok, why := h.p.TryQuiesce(0) // another change holds the lock
	if !ok {
		t.Fatal(why)
	}
	t.Cleanup(release)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	type outcome struct {
		res safety.Result
		err error
	}
	done := make(chan outcome, 2)
	go func() {
		res, err := h.p.Apply(ctx, desired("9.9.9.0/24"), nil, opts(false))
		done <- outcome{res, err}
	}()
	built := false
	go func() {
		res, err := h.p.ApplyBuilt(ctx, func(context.Context, []domain.ManagedRoute, *safety.Options) ([]domain.ManagedRoute, []domain.ManagedRule, error) {
			built = true
			return desired("8.8.8.0/24"), nil, nil
		}, opts(false))
		done <- outcome{res, err}
	}()
	for range 2 {
		select {
		case o := <-done:
			if !errors.Is(o.err, context.DeadlineExceeded) || o.res.Status != domain.TxFailed {
				t.Fatalf("gave up with %s %v", o.res.Status, o.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("still waiting for the lock after the caller's deadline")
		}
	}

	release()
	time.Sleep(50 * time.Millisecond)
	if n := h.prov.CountManaged(); n != 0 || built {
		t.Fatalf("a change went through after its caller gave up: %d route(s), built %v", n, built)
	}
	h.mustApply(t, desired("9.9.9.0/24")) // the lock is free
}

// ctxRoutesOutliveFlush is ctxProvider with macOS's flush, which leaves
// routes to the ownership records.
type ctxRoutesOutliveFlush struct{ *ctxProvider }

func (ctxRoutesOutliveFlush) FlushOwned(context.Context) error { return nil }

// A panic's flush runs to the end when its caller stops waiting (the
// uninstaller's timeout, a client going away): cut off, it would leave the
// routes it hadn't reached yet.
func TestPanicOutlivesItsCaller(t *testing.T) {
	h := newHarness(t)
	prov := ctxRoutesOutliveFlush{&ctxProvider{Provider: h.prov}}
	p := safety.NewProtocol(prov, h.st, h.clock, func() safety.Prober { return h.prober }, "fake", nil)
	if res, err := p.Apply(context.Background(), desired("9.9.9.0/24", "8.8.8.0/24"), nil, opts(false)); err != nil || res.Status != domain.TxPending {
		t.Fatalf("apply: %s %v", res.Status, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the caller is gone
	if err := p.Panic(ctx, domain.ActorUI); err != nil {
		t.Fatal(err)
	}
	if n := h.prov.CountManaged(); n != 0 {
		t.Fatalf("%d managed route(s) left", n)
	}
}
