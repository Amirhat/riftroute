package macos

import (
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

func vpnByName(name string) bool {
	for _, p := range []string{"utun", "ipsec", "ppp", "gpd"} {
		if len(name) >= len(p) && name[:len(p)] == p {
			return true
		}
	}
	return false
}

// The reported failure: with a point-to-point VPN up, the WINNING default is
// the tunnel's on-link route (no gateway address), so `route get default`
// yields nothing usable and exclude profiles died with "no physical gateway
// for v4". The physical gateway is in the table the whole time — find it.
func TestPickPhysicalDefaultIgnoresGatewaylessVPNDefault(t *testing.T) {
	// Mirrors the real table captured from the affected machine.
	routes := []domain.Route{
		{DstCIDR: "0.0.0.0/0", Gateway: "", Iface: "ipsec0", Family: domain.FamilyV4},
		{DstCIDR: "0.0.0.0/0", Gateway: "192.168.88.1", Iface: "en0", Family: domain.FamilyV4},
		{DstCIDR: "192.168.88.0/24", Gateway: "", Iface: "en0", Family: domain.FamilyV4},
	}
	gw, ifn, ok := pickPhysicalDefault(routes, vpnByName)
	if !ok {
		t.Fatal("physical gateway not found even though 192.168.88.1 via en0 is in the table")
	}
	if gw.String() != "192.168.88.1" || ifn != "en0" {
		t.Fatalf("picked %s via %s, want 192.168.88.1 via en0", gw, ifn)
	}
}

// A tunnel default that DOES carry a next-hop must still be rejected: routing
// "bypass" traffic through the VPN's own gateway would defeat exclude mode.
func TestPickPhysicalDefaultRejectsGatewayedVPNDefault(t *testing.T) {
	routes := []domain.Route{
		{DstCIDR: "0.0.0.0/0", Gateway: "10.8.0.1", Iface: "utun4", Family: domain.FamilyV4},
		{DstCIDR: "0.0.0.0/0", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4},
	}
	gw, ifn, ok := pickPhysicalDefault(routes, vpnByName)
	if !ok || gw.String() != "192.168.1.1" || ifn != "en0" {
		t.Fatalf("picked %s via %s (ok=%v), want the physical 192.168.1.1 via en0", gw, ifn, ok)
	}
}

// Model B / non-main tables must never be mistaken for the physical default.
func TestPickPhysicalDefaultSkipsNonMainTableAndReportsMiss(t *testing.T) {
	routes := []domain.Route{
		{DstCIDR: "0.0.0.0/0", Gateway: "10.8.0.1", Iface: "en0", Table: "5252", Family: domain.FamilyV4},
		{DstCIDR: "0.0.0.0/0", Gateway: "", Iface: "ipsec0", Family: domain.FamilyV4},
	}
	if _, _, ok := pickPhysicalDefault(routes, vpnByName); ok {
		t.Fatal("a table-5252 default (or a gateway-less tunnel) must not count as the physical gateway")
	}
}
