package tunnel

import (
	"context"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// The package's tests never probe the network: a full tunnel's liveness
// check runs only where a test asks for it.
func init() { aliveEvery = time.Hour }

// A full tunnel connected but passing nothing is ended after aliveMisses
// probes in a row, failed and saying why, so its routes and DNS leave; one
// probe that gets through resets the count; a tunnel that lists networks
// isn't probed.
func TestFullTunnelThatPassesNothingIsEnded(t *testing.T) {
	every := aliveEvery
	aliveEvery = 20 * time.Millisecond
	t.Cleanup(func() { aliveEvery = every })
	var alive atomic.Bool
	var asked atomic.Int32
	h := newHarness(t)
	h.m.o.Probe = func(_ context.Context, dns []netip.Addr) bool {
		asked.Add(1)
		return alive.Load()
	}
	go h.m.watchAlive() // New started one with the hour-long tick
	ctx := context.Background()

	if _, err := h.m.Save(ctx, infraSpec()); err != nil { // lists networks
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
	time.Sleep(10 * aliveEvery)
	if asked.Load() != 0 {
		t.Fatal("a tunnel that lists networks was probed")
	}

	on := true
	spec := infraSpec()
	spec.AllTraffic = &on
	alive.Store(true)
	if _, err := h.m.Save(ctx, spec); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
	waitFor(t, "probes", func() bool { return asked.Load() >= int32(2*aliveMisses) })
	if st, _ := h.m.Status("infra"); st.State != domain.TunnelConnected {
		t.Fatalf("ended though traffic gets through: %+v", st)
	}

	alive.Store(false)
	st := waitState(t, h.m, "infra", domain.TunnelFailed)
	if !strings.Contains(st.LastError, "nothing got through it") {
		t.Fatalf("last error %q", st.LastError)
	}
	for _, in := range h.lastApply() {
		if in.Iface != "" {
			t.Fatalf("its routes stayed: %+v", in)
		}
	}
}
