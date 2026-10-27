package safety_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/safety"
)

// gatewayCaptured reports whether the guardrails refuse dst (into a tunnel,
// so only the gateway-capture rule can) for capturing the gateway.
func gatewayCaptured(t *testing.T, prov *fake.Provider, dst string) bool {
	t.Helper()
	desired := []domain.ManagedRoute{{Route: domain.Route{DstCIDR: dst, Iface: "utun7", Family: domain.FamilyV4, Owner: domain.OwnerRiftRoute}, ProfileID: "tunnel:all"}}
	for _, v := range safety.CheckGuardrails(context.Background(), prov, desired, netip.MustParseAddr("192.168.1.1")) {
		if v.Rule == "gateway-capture" {
			return true
		}
	}
	return false
}

// A route holding the physical gateway is refused — unless it's wider than
// the network the gateway is on (its connected route), which keeps winning
// for the gateway: a full tunnel's 192.0.0.0/2, or 192.168.0.0/16, around
// the fake's 192.168.1.0/24 LAN. One as narrow as the LAN, or narrower, is
// still refused, and so is any of them without the connected route.
func TestGatewayCaptureAllowsRoutesWiderThanTheLAN(t *testing.T) {
	prov := fake.New()
	for dst, want := range map[string]bool{
		"192.0.0.0/2":    false,
		"192.168.0.0/16": false,
		"192.168.1.0/24": true,
		"192.168.1.0/25": true,
		"192.168.1.1/32": true,
		"10.0.0.0/8":     false, // doesn't hold it at all
	} {
		if got := gatewayCaptured(t, prov, dst); got != want {
			t.Errorf("%s: refused = %v, want %v", dst, got, want)
		}
	}

	prov.PurgeIface("en0") // no connected route holds the gateway now
	if !gatewayCaptured(t, prov, "192.0.0.0/2") {
		t.Error("192.0.0.0/2 allowed with no connected route holding the gateway")
	}
}
