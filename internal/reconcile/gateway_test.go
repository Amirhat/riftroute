package reconcile_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

// The guardrails vet a desired set against the gateway it was built for. The
// network moving between an early gateway read and the build's would vet a
// set built for the new gateway against the old one: here 10.0.0.0/8 via the
// new router 10.0.0.1 — a route capturing its own gateway — passed the
// gateway-capture check because it was run against 192.168.1.1.
func TestReconcileVetsAgainstTheGatewayItBuiltFor(t *testing.T) {
	h := newTunnelHarness(t)
	h.autoApply.Store(true)
	directProfile(t, h.st, "10.0.0.0/8")
	ctx := context.Background()
	h.prov.hook(&h.prov.afterGateway, func() { // Wi-Fi → Ethernet, right after the first read
		h.prov.PurgeIface("en0")
		if err := h.prov.AddRoute(ctx, domain.ManagedRoute{Route: domain.Route{DstCIDR: "10.0.0.0/24", Iface: "en7", Family: domain.FamilyV4}}); err != nil {
			t.Error(err)
		}
		h.prov.SetPhysGateway(domain.FamilyV4, netip.MustParseAddr("10.0.0.1"), "en7")
	})

	res, _ := h.rec.Reconcile(ctx)
	rs, err := h.prov.ListRoutes(ctx, domain.FamilyV4)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		pfx, err := netip.ParsePrefix(r.DstCIDR)
		gw, gerr := netip.ParseAddr(r.Gateway)
		if r.Owner == domain.OwnerRiftRoute && err == nil && gerr == nil && pfx.Contains(gw) {
			t.Fatalf("installed %s via %s, capturing its own gateway (%s: %v)", r.DstCIDR, r.Gateway, res.Status, res.Violations)
		}
	}
}
