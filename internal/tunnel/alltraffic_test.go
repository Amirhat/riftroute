package tunnel

import (
	"context"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

// A full tunnel (all traffic) is saved and reported as one, its input says
// so once it's connected, a client that doesn't send the setting keeps it,
// false turns it off, and it takes an IPv6 address when offered.
func TestSaveAllTraffic(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	on, off := true, false
	spec := infraSpec()
	spec.AllTraffic = &on
	st, err := h.m.Save(ctx, spec)
	if err != nil || !st.AllTraffic {
		t.Fatalf("saved: %+v, %v", st, err)
	}
	h.m.mu.Lock()
	needs := h.m.defs["infra"].needsIPv6()
	h.m.mu.Unlock()
	if !needs {
		t.Error("a full tunnel doesn't ask for IPv6")
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
	if in := h.lastApply(); len(in) != 1 || !in[0].AllTraffic || in[0].Iface == "" {
		t.Fatalf("inputs = %+v", in)
	}

	if st, err := h.m.Save(ctx, infraSpec()); err != nil || !st.AllTraffic {
		t.Fatalf("an old client's edit dropped it: %+v, %v", st, err)
	}
	// Turning it off changes whether it asks for IPv6: that's settled at
	// connect, so it reconnects.
	starts := h.fl.Starts()
	spec.AllTraffic = &off
	if st, err := h.m.Save(ctx, spec); err != nil || st.AllTraffic {
		t.Fatalf("turned off: %+v, %v", st, err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
	if h.fl.Starts() == starts {
		t.Error("it didn't reconnect, so it still asks for IPv6")
	}
	if in := h.lastApply(); len(in) != 1 || in[0].AllTraffic {
		t.Fatalf("inputs after turning it off = %+v", in)
	}
}

// 0.0.0.0/0 as a listed route is still refused, and the reason points at
// the setting.
func TestDefaultRouteListedPointsAtAllTraffic(t *testing.T) {
	_, errs := normalizeRoutes([]string{"0.0.0.0/0"})
	if len(errs) != 1 || !strings.Contains(errs[0], "--all-traffic") {
		t.Fatalf("errs = %v", errs)
	}
}
