package reconcile_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/routing"
	"github.com/Amirhat/riftroute/internal/safety"
)

// blip takes the network away for longer than the watchdog tolerates.
func (h *tunnelHarness) blip(t *testing.T) {
	t.Helper()
	for _, a := range safety.DefaultAnchors(netip.MustParseAddr("192.168.1.1")) {
		h.prober.SetReachable(a, false)
	}
	for range 10 {
		h.clock.Advance(time.Second)
		time.Sleep(5 * time.Millisecond) // let a watchdog probe and re-arm
	}
	for _, a := range safety.DefaultAnchors(netip.MustParseAddr("192.168.1.1")) {
		h.prober.SetReachable(a, true)
	}
}

// A tunnel transition commits at once: nothing it changes can cut the
// gateway, a resolver or an anchor, and a watchdog rolling it back did harm.
// A network blip right after a connect must not withdraw the live tunnel's
// routes (nothing would put them back); one right after a disconnect must not
// re-add them — the pin re-added while the on-link route fails (its utun is
// gone) was left in the kernel unrecorded, with the journal entry kept.
func TestTunnelTransitionsSurviveANetworkBlip(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	infra := routing.TunnelInput{Name: "infra", Iface: "utun9", Routes: []string{"192.168.70.0/24"}, Bypass: []netip.Addr{netip.MustParseAddr("198.51.100.7")}}

	h.setTunnels(infra)
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	if busy, _ := h.proto.Busy(); busy {
		t.Fatal("a tunnel connect left a transaction on probation")
	}
	h.blip(t)
	k := h.kernel(t)
	if got := k["192.168.70.0/24"]; len(got) != 1 || got[0] != "utun9" {
		t.Fatalf("a blip after the connect withdrew the tunnel's route: %v", k)
	}
	if got := k["198.51.100.7/32"]; len(got) != 1 || got[0] != "en0" {
		t.Fatalf("a blip after the connect withdrew the tunnel's pin: %v", k)
	}

	h.setTunnels() // disconnect: openvpn closes utun9
	h.prov.SetTunnelIface("utun9", "", false)
	h.prov.PurgeIface("utun9")
	h.prov.FailAddRoute("192.168.70.0/24", true) // no utun9 to add it into
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	h.blip(t)
	k = h.kernel(t)
	for _, dst := range []string{"192.168.70.0/24", "198.51.100.7/32"} {
		if len(k[dst]) != 0 {
			t.Errorf("%s back in the kernel via %v after a blip", dst, k[dst])
		}
	}
	for _, o := range h.ownedTunnelRoutes(t) {
		t.Errorf("still recorded: %+v", o)
	}
	if pend, err := h.st.ListPendingTx(); err != nil || len(pend) != 0 {
		t.Errorf("journal = %v %v, want empty", pend, err)
	}
}
