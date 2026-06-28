package safety_test

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/store"
)

// harness wires the Apply Protocol over the fake provider with a controllable
// clock + prober so the entire §2.5 failure & recovery matrix is deterministic
// and host-safe.
type harness struct {
	p      *safety.Protocol
	prov   *fake.Provider
	st     *store.Store
	clock  *safety.FakeClock
	prober *safety.FakeProber
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	prov := fake.New()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	clock := safety.NewFakeClock(time.Unix(0, 0))
	prober := safety.NewFakeProber()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := safety.NewProtocol(prov, st, clock, func() safety.Prober { return prober }, "fake", log)
	return &harness{p: p, prov: prov, st: st, clock: clock, prober: prober}
}

func desired(cidrs ...string) []domain.ManagedRoute {
	var out []domain.ManagedRoute
	for _, c := range cidrs {
		out = append(out, domain.ManagedRoute{
			Route:     domain.Route{DstCIDR: c, Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4, Owner: domain.OwnerRiftRoute},
			ProfileID: "p1",
		})
	}
	return out
}

func opts(interactive bool) safety.Options {
	return safety.Options{
		Interactive:    interactive,
		Anchors:        []string{"192.168.1.1"},
		K:              1,
		ProbeInterval:  time.Second,
		ConfirmTimeout: 15 * time.Second,
		GuardWindow:    30 * time.Second,
		Actor:          domain.ActorUI,
		PhysGW:         netip.MustParseAddr("192.168.1.1"),
	}
}

// Row 1: op k of N fails mid-apply → inverse of 1..k-1 runs; state restored.
func TestMatrix_OpFailureRollsBackPartial(t *testing.T) {
	h := newHarness(t)
	h.prov.FailAddRoute("9.9.9.0/24", true) // the second add fails
	res, err := h.p.Apply(context.Background(), desired("1.1.1.0/24", "9.9.9.0/24"), nil, opts(false))
	if err != nil {
		t.Fatalf("apply returned hard error: %v", err)
	}
	if res.Status != domain.TxFailed {
		t.Fatalf("want failed, got %s", res.Status)
	}
	if h.prov.CountManaged() != 0 {
		t.Fatalf("partial state not rolled back: %d managed routes remain", h.prov.CountManaged())
	}
	owned, _ := h.st.ListOwned()
	if len(owned) != 0 {
		t.Fatalf("ownership recorded for a failed apply: %d", len(owned))
	}
}

// Row 2: anchor unreachable after apply → watchdog fires rollback within K probes.
func TestMatrix_WatchdogRollsBackOnAnchorLoss(t *testing.T) {
	h := newHarness(t)
	h.prober.SetReachable("192.168.1.1", false) // anchor down
	res, err := h.p.Apply(context.Background(), desired("9.9.9.0/24"), nil, opts(false))
	if err != nil || res.Status != domain.TxPending {
		t.Fatalf("apply: status=%s err=%v", res.Status, err)
	}
	if h.prov.CountManaged() != 1 {
		t.Fatalf("route should be applied before the guard fires")
	}
	h.clock.Advance(time.Second) // one probe, K=1 → fire
	result, _ := h.p.Wait(res.TxID)
	if result != domain.TxRolledBack {
		t.Fatalf("watchdog should have rolled back, got %s", result)
	}
	if h.prov.CountManaged() != 0 {
		t.Fatalf("watchdog rollback left %d routes", h.prov.CountManaged())
	}
}

// Row 3: interactive apply never confirmed → auto-revert at confirm_timeout.
func TestMatrix_MissedConfirmAutoReverts(t *testing.T) {
	h := newHarness(t)
	res, err := h.p.Apply(context.Background(), desired("9.9.9.0/24"), nil, opts(true))
	if err != nil || !res.NeedsConfirm {
		t.Fatalf("interactive apply should need confirm: %+v err=%v", res, err)
	}
	if h.prov.CountManaged() != 1 {
		t.Fatal("route should be applied pending confirm")
	}
	h.clock.Advance(15 * time.Second) // confirm window elapses, no confirm
	result, _ := h.p.Wait(res.TxID)
	if result != domain.TxRolledBack {
		t.Fatalf("missed confirm should auto-revert, got %s", result)
	}
	if h.prov.CountManaged() != 0 {
		t.Fatalf("auto-revert left %d routes", h.prov.CountManaged())
	}
}

// Happy path: confirm within the window keeps the change.
func TestMatrix_ConfirmKeepsChange(t *testing.T) {
	h := newHarness(t)
	res, _ := h.p.Apply(context.Background(), desired("9.9.9.0/24"), nil, opts(true))
	result, err := h.p.Confirm(res.TxID)
	if err != nil || result != domain.TxCommitted {
		t.Fatalf("confirm: result=%s err=%v", result, err)
	}
	h.clock.Advance(30 * time.Second) // past the window — must NOT roll back
	if h.prov.CountManaged() != 1 {
		t.Fatalf("confirmed route should remain, got %d", h.prov.CountManaged())
	}
	owned, _ := h.st.ListOwned()
	if len(owned) != 1 {
		t.Fatalf("ownership not recorded on commit: %d", len(owned))
	}
}

// Non-interactive: guard window elapses cleanly → auto-commit.
func TestMatrix_GuardWindowAutoCommits(t *testing.T) {
	h := newHarness(t)
	res, _ := h.p.Apply(context.Background(), desired("9.9.9.0/24"), nil, opts(false))
	h.clock.Advance(30 * time.Second)
	result, _ := h.p.Wait(res.TxID)
	if result != domain.TxCommitted {
		t.Fatalf("clean guard window should commit, got %s", result)
	}
	if h.prov.CountManaged() != 1 {
		t.Fatalf("committed route missing, got %d", h.prov.CountManaged())
	}
}

// Row 4: daemon crash mid-transaction → ownership reconcile repairs partial state.
func TestMatrix_CrashRecoveryReconciles(t *testing.T) {
	h := newHarness(t)
	// Commit two managed routes cleanly.
	res, _ := h.p.Apply(context.Background(), desired("1.1.1.0/24", "2.2.2.0/24"), nil, opts(true))
	if _, err := h.p.Confirm(res.TxID); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Simulate a crash mid-next-transaction: an orphan route exists in the kernel
	// but not in the ownership DB, and a DB-owned route is missing from the kernel.
	orphan := domain.ManagedRoute{Route: domain.Route{DstCIDR: "3.3.3.0/24", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4, Owner: domain.OwnerRiftRoute}}
	if err := h.prov.AddRoute(ctx, orphan); err != nil {
		t.Fatal(err)
	}
	missing := domain.ManagedRoute{Route: domain.Route{DstCIDR: "2.2.2.0/24", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4, Owner: domain.OwnerRiftRoute}}
	if err := h.prov.DelRoute(ctx, missing); err != nil {
		t.Fatal(err)
	}

	added, removed, err := h.p.ReconcileOwnership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 || removed != 1 {
		t.Fatalf("reconcile want added=1 removed=1, got added=%d removed=%d", added, removed)
	}
	// Kernel must now match the ownership DB (the two committed routes).
	if h.prov.CountManaged() != 2 {
		t.Fatalf("after reconcile want 2 managed, got %d", h.prov.CountManaged())
	}
}

// Row 5: a second apply while one is pending is rejected (serialized).
func TestMatrix_AppliesSerialized(t *testing.T) {
	h := newHarness(t)
	res1, _ := h.p.Apply(context.Background(), desired("9.9.9.0/24"), nil, opts(true))
	_, err := h.p.Apply(context.Background(), desired("1.1.1.0/24"), nil, opts(true))
	if err != safety.ErrApplyInProgress {
		t.Fatalf("want ErrApplyInProgress, got %v", err)
	}
	// resolve the first so the harness cleans up.
	_, _ = h.p.Confirm(res1.TxID)
}

// Row 6: a next-hop that isn't on-link (only reachable via the VPN) is refused.
func TestMatrix_GuardrailRefusesBadGateway(t *testing.T) {
	h := newHarness(t)
	bad := []domain.ManagedRoute{{
		Route: domain.Route{DstCIDR: "9.9.9.0/24", Gateway: "10.99.99.99", Iface: "en0", Family: domain.FamilyV4, Owner: domain.OwnerRiftRoute},
	}}
	res, err := h.p.Apply(context.Background(), bad, nil, opts(false))
	if err != safety.ErrGuardrail {
		t.Fatalf("want ErrGuardrail, got %v", err)
	}
	if len(res.Violations) == 0 {
		t.Fatal("expected violations")
	}
	if h.prov.CountManaged() != 0 {
		t.Fatalf("refused apply must not install routes, got %d", h.prov.CountManaged())
	}
}

// Row 7: panic removes all managed routes from any state and is idempotent.
func TestMatrix_PanicIdempotent(t *testing.T) {
	h := newHarness(t)
	res, _ := h.p.Apply(context.Background(), desired("1.1.1.0/24", "2.2.2.0/24"), nil, opts(true))
	_, _ = h.p.Confirm(res.TxID)
	if h.prov.CountManaged() != 2 {
		t.Fatalf("setup: want 2 managed, got %d", h.prov.CountManaged())
	}
	ctx := context.Background()
	if err := h.p.Panic(ctx, domain.ActorUI); err != nil {
		t.Fatal(err)
	}
	if h.prov.CountManaged() != 0 {
		t.Fatalf("panic left %d managed routes", h.prov.CountManaged())
	}
	owned, _ := h.st.ListOwned()
	if len(owned) != 0 {
		t.Fatalf("panic left %d ownership records", len(owned))
	}
	// idempotent: a second panic from the clean state is a no-op success.
	if err := h.p.Panic(ctx, domain.ActorUI); err != nil {
		t.Fatalf("second panic errored: %v", err)
	}
	if h.prov.CountManaged() != 0 {
		t.Fatal("second panic disturbed state")
	}
}
