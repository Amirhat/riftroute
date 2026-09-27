package reconcile_test

import (
	"context"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/routing"
	"github.com/Amirhat/riftroute/internal/safety"
)

func (h *tunnelHarness) tunnelProfile(t *testing.T, enabled bool, dsts ...string) {
	t.Helper()
	var rules []domain.Rule
	for _, d := range dsts {
		rules = append(rules, domain.Rule{Type: domain.RuleCIDR, Value: d})
	}
	if err := h.st.UpsertProfile(domain.Profile{ID: "via-con3", Name: "via con3", Enabled: enabled, Mode: domain.ModeTunnel,
		Tunnel: "con3", Rules: rules}); err != nil {
		t.Fatal(err)
	}
}

// fullApply runs the auto-apply path and lets its guard window commit it.
func (h *tunnelHarness) fullApply(t *testing.T) {
	t.Helper()
	tx := h.fullApplyOnProbation(t)
	h.clock.Advance(30 * time.Second)
	if got, _ := h.proto.Wait(tx); got != domain.TxCommitted {
		t.Fatalf("the full apply: %s", got)
	}
}

var con3 = routing.TunnelInput{Name: "con3", Iface: "utun8"}

// A tunnel-mode profile's destinations go into its tunnel while it's up —
// not around the main VPN — and turning the profile off takes them out,
// with the tunnel still up.
func TestProfileRoutesThroughItsTunnel(t *testing.T) {
	h := newTunnelHarness(t)
	h.setTunnels(con3)
	h.tunnelProfile(t, true, "9.9.9.9/32", "10.20.0.0/24")
	h.fullApply(t)
	k := h.kernel(t)
	for _, dst := range []string{"9.9.9.9/32", "10.20.0.0/24"} {
		if got := k[dst]; len(got) != 1 || got[0] != "utun8" {
			t.Errorf("%s = %v, want into utun8", dst, got)
		}
	}

	h.tunnelProfile(t, false, "9.9.9.9/32", "10.20.0.0/24")
	h.fullApply(t)
	k = h.kernel(t)
	if len(k["9.9.9.9/32"]) != 0 || len(k["10.20.0.0/24"]) != 0 {
		t.Errorf("a profile turned off still routes into the tunnel: %v %v", k["9.9.9.9/32"], k["10.20.0.0/24"])
	}
}

// With auto-apply off, a tunnel event installs the tunnel-mode profiles'
// destinations as the last full apply committed them: an edit saved but not
// applied doesn't reach the kernel that way.
func TestTunnelEventRoutesTheAppliedProfileNotTheStoredOne(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	h.setTunnels(con3)
	h.tunnelProfile(t, true, "9.9.9.9/32")
	h.fullApply(t)
	h.tunnelProfile(t, true, "9.9.9.9/32", "10.30.0.0/24") // saved, not applied

	h.setTunnels() // disconnected…
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.kernel(t)["9.9.9.9/32"]; len(got) != 0 {
		t.Fatalf("a down tunnel's profile route stayed: %v", got)
	}
	h.setTunnels(con3) // …and connected again
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	k := h.kernel(t)
	if got := k["9.9.9.9/32"]; len(got) != 1 || got[0] != "utun8" {
		t.Errorf("the applied destination = %v, want back into utun8", got)
	}
	if got := k["10.30.0.0/24"]; len(got) != 0 {
		t.Errorf("an edit that was never applied was installed: %v", got)
	}
}

// A panic flushes the tunnel-mode profiles' routes; the tunnel apply that
// follows doesn't put them back.
func TestPanicForgetsTheProfileRoutes(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	h.setTunnels(con3)
	h.tunnelProfile(t, true, "9.9.9.9/32")
	h.fullApply(t)
	if err := h.proto.PanicWith(ctx, domain.ActorUI, safety.PanicSteps{Flushing: h.svc.ForgetRecords}); err != nil {
		t.Fatal(err)
	}
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.kernel(t)["9.9.9.9/32"]; len(got) != 0 {
		t.Errorf("a flushed profile route came back: %v", got)
	}
}
