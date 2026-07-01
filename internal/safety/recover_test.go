package safety_test

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/safety"
)

// A crash mid-transaction — or while a non-interactive change is on probation —
// must revert to the pre-change state on restart. The write-ahead journal
// guarantees this even on macOS, where kernel routes carry no owner tag to
// reattribute. This is the host-safety backstop for SIGKILL / power loss.
func TestRecoverPending_RevertsInFlightTx(t *testing.T) {
	h := newHarness(t)
	// Interactive apply: route installed + journaled, but never confirmed → the tx
	// is still pending (its journal entry survives a "crash").
	res, err := h.p.Apply(context.Background(), desired("9.9.9.0/24"), nil, opts(true))
	if err != nil || !res.NeedsConfirm {
		t.Fatalf("apply: %+v err=%v", res, err)
	}
	if h.prov.CountManaged() != 1 {
		t.Fatal("route should be installed pending confirm")
	}

	// Simulate crash + restart: a brand-new Protocol over the SAME store+provider.
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p2 := safety.NewProtocol(h.prov, h.st, safety.NewFakeClock(time.Unix(0, 0)),
		func() safety.Prober { return safety.NewFakeProber() }, "fake", log)

	n, err := p2.RecoverPending(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("RecoverPending n=%d err=%v", n, err)
	}
	if h.prov.CountManaged() != 0 {
		t.Fatalf("crash recovery must revert the in-flight route, got %d managed", h.prov.CountManaged())
	}
	owned, _ := h.st.ListOwned()
	if len(owned) != 0 {
		t.Fatalf("ownership should be reverted too, got %d", len(owned))
	}
	// Journal cleared → recovery is idempotent.
	if n2, _ := p2.RecoverPending(context.Background()); n2 != 0 {
		t.Fatalf("recovery should be idempotent, got %d", n2)
	}
}

// If the physical gateway can't be read (transient failure during DHCP/link
// turbulence), the gateway-capture guard can't be evaluated — so any main-table
// change must be REFUSED (fail-safe), not applied with the guard silently off.
func TestGuardrail_RefusesMainTableWhenGatewayUnknown(t *testing.T) {
	h := newHarness(t)
	o := opts(false)
	o.PhysGW = netip.Addr{} // gateway unreadable
	res, err := h.p.Apply(context.Background(), desired("9.9.9.0/24"), nil, o)
	if err != safety.ErrGuardrail {
		t.Fatalf("want ErrGuardrail when gateway is unknown, got err=%v status=%s", err, res.Status)
	}
	if h.prov.CountManaged() != 0 {
		t.Fatalf("nothing should be applied on a fail-safe refusal, got %d", h.prov.CountManaged())
	}
}
