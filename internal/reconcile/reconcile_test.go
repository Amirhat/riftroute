package reconcile_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/netmon"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/reconcile"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/store"
)

func setup(t *testing.T) (*reconcile.Reconciler, *fake.Provider, *store.Store, *safety.FakeClock) {
	t.Helper()
	prov := fake.New()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	// an enabled exclude profile so auto-apply has a bypass to install.
	if err := st.UpsertProfile(domain.Profile{
		ID: "p1", Name: "direct", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "9.9.9.0/24"}},
	}); err != nil {
		t.Fatal(err)
	}
	clk := safety.NewFakeClock(time.Unix(0, 0))
	svc := core.New(prov, st, "test")
	proto := safety.NewProtocol(prov, st, clk, func() safety.Prober { return safety.NewFakeProber() }, "fake", nil)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rec := reconcile.New(svc, proto, log, 0 /* no debounce */, func() bool { return true })
	return rec, prov, st, clk
}

func TestReconcileInstallsDesired(t *testing.T) {
	rec, prov, _, _ := setup(t)
	res, err := rec.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Status != domain.TxPending {
		t.Fatalf("expected pending (guard armed), got %s", res.Status)
	}
	if prov.CountManaged() != 1 {
		t.Fatalf("auto-apply should install the bypass, got %d managed", prov.CountManaged())
	}
}

func TestReconcileActorIsDaemonAuto(t *testing.T) {
	rec, _, st, _ := setup(t)
	if _, err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	evs, err := st.ListAudit(time.Time{}, 10)
	if err != nil || len(evs) == 0 {
		t.Fatalf("audit: %v len=%d", err, len(evs))
	}
	if evs[0].Actor != domain.ActorDaemon {
		t.Fatalf("auto-apply audit actor should be daemon-auto, got %s", evs[0].Actor)
	}
}

func TestRunReconcilesOnEvent(t *testing.T) {
	rec, prov, _, _ := setup(t)
	mon := netmon.NewFakeMonitor()
	done := make(chan struct{}, 4)
	rec.SetTestHook(func(safety.Result, error) { done <- struct{}{} })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rec.Run(ctx, mon.Events())

	mon.Emit(netmon.Event{Type: netmon.EventVPNUp, Iface: "utun3"})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reconcile did not run after VPNUp event")
	}
	if prov.CountManaged() != 1 {
		t.Fatalf("event-driven auto-apply should install the bypass, got %d", prov.CountManaged())
	}
}

func TestDisabledAutoApplyNoop(t *testing.T) {
	prov := fake.New()
	st, _ := store.Open(":memory:")
	t.Cleanup(func() { _ = st.Close() })
	_ = st.UpsertProfile(domain.Profile{ID: "p1", Name: "d", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "9.9.9.0/24"}}})
	svc := core.New(prov, st, "test")
	proto := safety.NewProtocol(prov, st, safety.NewFakeClock(time.Unix(0, 0)), func() safety.Prober { return safety.NewFakeProber() }, "fake", nil)
	rec := reconcile.New(svc, proto, slog.New(slog.NewTextHandler(io.Discard, nil)), 0, func() bool { return false })
	if _, err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if prov.CountManaged() != 0 {
		t.Fatal("disabled auto-apply must not change routes")
	}
}
