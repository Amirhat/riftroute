package routing

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

// byDestination groups a desired set by what the kernel keeps one route per.
func byDestination(desired []domain.ManagedRoute) map[string][]domain.ManagedRoute {
	out := map[string][]domain.ManagedRoute{}
	for _, d := range desired {
		out[dstKey(d.Route)] = append(out[dstKey(d.Route)], d)
	}
	return out
}

// oneRoutePerDestination fails the test when the desired set carries a
// destination twice — the guardrails refuse the WHOLE apply over that.
func oneRoutePerDestination(t *testing.T, desired []domain.ManagedRoute) {
	t.Helper()
	for k, rs := range byDestination(desired) {
		if len(rs) > 1 {
			t.Errorf("destination %s is routed %d times: %+v", k, len(rs), rs)
		}
	}
}

// Two connected tunnels listing the same network: the first (by name) gets
// it, the second reports it blocked — the desired set never carries one
// destination twice, which would refuse every apply while both are up.
func TestTunnelsNeverClaimOneDestinationTwice(t *testing.T) {
	in := testInput()
	in.Tunnels = []TunnelInput{
		{Name: "b", Iface: "utun7", Routes: []string{"10.20.0.0/16", "10.30.0.0/16"}},
		{Name: "a", Iface: "utun6", Routes: []string{"10.20.0.0/16"}},
	}
	desired, _, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	oneRoutePerDestination(t, desired)
	got := map[string]string{}
	for _, d := range desired {
		got[d.DstCIDR] = d.ProfileID
	}
	if got["10.20.0.0/16"] != "tunnel:a" || got["10.30.0.0/16"] != "tunnel:b" {
		t.Fatalf("desired = %v", got)
	}
	tp := PlanTunnels(in)
	if bs := tp.Blocked["b"]; len(bs) != 1 || bs[0].Route != "10.20.0.0/16" || !strings.Contains(bs[0].Reason, "tunnel a") {
		t.Fatalf("blocked = %+v", tp.Blocked)
	}
}

// A tunnel that lists its own server (via: direct): the pin and the on-link
// route would share a destination. The pin wins — sending the server into its
// own tunnel would loop the connection.
func TestTunnelListingItsOwnServerKeepsThePin(t *testing.T) {
	in := testInput()
	server := netip.MustParseAddr("198.51.100.7")
	in.Tunnels = []TunnelInput{{Name: "infra", Iface: "utun6", Routes: []string{"198.51.100.7", "192.168.70.0/24"}, Bypass: []netip.Addr{server}}}
	desired, _, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	oneRoutePerDestination(t, desired)
	for _, d := range desired {
		if d.DstCIDR == "198.51.100.7/32" && d.Gateway != "192.168.1.1" {
			t.Fatalf("the server went into the tunnel: %+v", d)
		}
	}
	if bs := PlanTunnels(in).Blocked["infra"]; len(bs) != 1 || !strings.Contains(bs[0].Reason, "own server") {
		t.Fatalf("blocked = %+v", bs)
	}
}

// Aggregation must not merge a tunnel's destinations into a prefix another
// tunnel already routes: the halves go in as listed instead.
func TestTunnelAggregateNeverLandsOnAClaimedDestination(t *testing.T) {
	in := testInput()
	in.Tunnels = []TunnelInput{
		{Name: "a", Iface: "utun6", Routes: []string{"10.0.0.0/24"}},
		{Name: "b", Iface: "utun7", Routes: []string{"10.0.0.0/25", "10.0.0.128/25"}},
	}
	desired, _, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	oneRoutePerDestination(t, desired)
	got := map[string]string{}
	for _, d := range desired {
		got[d.DstCIDR] = d.Iface
	}
	if got["10.0.0.0/24"] != "utun6" || got["10.0.0.0/25"] != "utun7" || got["10.0.0.128/25"] != "utun7" {
		t.Fatalf("desired = %v", got)
	}
}

// A pin and a profile route for the same server with different next hops
// would conflict: the profile's route carries the server, the pin is left out.
func TestTunnelPinYieldsToAProfileRouteForTheServer(t *testing.T) {
	p := domain.Profile{
		ID: "p1", Name: "gw", Enabled: true, Mode: domain.ModeExclude, Gateway: "192.168.1.254",
		Rules: []domain.Rule{{Type: domain.RuleIP, Value: "198.51.100.7"}},
	}
	in := testInput(p)
	in.Tunnels = []TunnelInput{{Name: "infra", Bypass: []netip.Addr{netip.MustParseAddr("198.51.100.7")}}}
	desired, _, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	oneRoutePerDestination(t, desired)
	if len(desired) != 1 || desired[0].ProfileID != "p1" {
		t.Fatalf("desired = %+v", desired)
	}
}

// Exclude profiles yield only to networks a tunnel really routes: one that is
// still connecting (no interface) routes nothing, and neither does a v4-only
// tunnel for its v6 destinations.
func TestExcludeProfileYieldsOnlyToLiveTunnelNetworks(t *testing.T) {
	work := domain.Profile{
		ID: "work", Name: "WORK", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleIP, Value: "192.168.70.42"}, {Type: domain.RuleIP, Value: "fd00::42"}},
	}
	in := testInput(work)
	in.GatewayV6, in.PhysIfaceV6 = netip.MustParseAddr("fe80::1"), "en0"

	in.Tunnels = []TunnelInput{{Name: "infra", Routes: []string{"192.168.70.0/24"}}} // connecting
	desired, _, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	if byDestination(desired)["v4||192.168.70.42/32"] == nil {
		t.Errorf("the tunnel isn't up; the exclude route must stay: %+v", desired)
	}

	in.Tunnels = []TunnelInput{{Name: "infra", Iface: "utun6", Routes: []string{"192.168.70.0/24", "fd00::/8"}}} // v4 only
	if desired, _, err = BuildDesired(in); err != nil {
		t.Fatal(err)
	}
	got := byDestination(desired)
	if got["v4||192.168.70.42/32"] != nil {
		t.Error("192.168.70.42 is behind the live tunnel; the exclude route must yield")
	}
	if got["v6||fd00::42/128"] == nil {
		t.Errorf("the tunnel carries no IPv6, so fd00::/8 isn't behind it; the exclude route must stay: %+v", desired)
	}
	if bs := PlanTunnels(in).Blocked["infra"]; len(bs) != 1 || bs[0].Route != "fd00::/8" || !strings.Contains(bs[0].Reason, "no IPv6") {
		t.Errorf("blocked = %+v", bs)
	}
}

// The kernel check must recognize our routes however the table spells them —
// else a route reads as always missing and every apply re-adds it: masked
// destinations, a link-local gateway with a zone (our record) or with its
// scope embedded in the address (the macOS RIB). Clone entries aren't routes.
func TestInstalledRecognizesOurRoutes(t *testing.T) {
	in := IndexInstalled([]domain.Route{
		{DstCIDR: "192.168.70.0/24", Iface: "utun6", Family: domain.FamilyV4},
		{DstCIDR: "2001:db8::/32", Gateway: "fe80:4::1", Iface: "en0", Family: domain.FamilyV6},
		{DstCIDR: "198.51.100.7/32", Gateway: "10.8.0.1", Iface: "utun3", Family: domain.FamilyV4, Cloned: true},
	})
	for _, r := range []domain.Route{
		{DstCIDR: "192.168.70.1/24", Iface: "utun6", Family: domain.FamilyV4},
		{DstCIDR: "2001:db8::/32", Gateway: "fe80::1%en0", Iface: "en0", Family: domain.FamilyV6},
	} {
		if !in.Has(r) {
			t.Errorf("%+v not recognized", r)
		}
	}
	for _, r := range []domain.Route{
		{DstCIDR: "192.168.70.0/24", Iface: "utun7", Family: domain.FamilyV4},
		{DstCIDR: "198.51.100.7/32", Gateway: "10.8.0.1", Iface: "utun3", Family: domain.FamilyV4},
	} {
		if in.Has(r) {
			t.Errorf("%+v isn't there", r)
		}
	}
}

// A route that contains the tunnel's own server with nothing holding the
// server off the tunnel (via: default pins nothing; a pin can be lost) sends
// openvpn's packets into its own tunnel: it can never reconnect, and the
// listed networks blackhole. The route is left out, the rest still installs.
func TestTunnelRouteContainingItsOwnServerNeedsAPin(t *testing.T) {
	server := netip.MustParseAddr("198.51.100.7")
	tunnelRoutes := func(in DesiredInput) string {
		t.Helper()
		desired, _, err := BuildDesired(in)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, d := range desired {
			if d.Gateway == "" {
				out = append(out, d.DstCIDR)
			}
		}
		return strings.Join(out, ",")
	}

	// via: direct, but the pin can't be made (no physical gateway for it).
	in := testInput()
	in.GatewayV4 = netip.Addr{}
	in.Tunnels = []TunnelInput{{Name: "infra", Iface: "utun6", Routes: []string{"198.51.100.0/24", "192.168.70.0/24"}, Bypass: []netip.Addr{server}}}
	if got := tunnelRoutes(in); got != "192.168.70.0/24" {
		t.Errorf("unpinned: tunnel routes = %s, want only 192.168.70.0/24", got)
	}
	if bs := PlanTunnels(in).Blocked["infra"]; len(bs) != 1 || !strings.Contains(bs[0].Reason, "own server 198.51.100.7") {
		t.Errorf("unpinned: blocked = %+v", bs)
	}

	// via: default — the manager reports the servers without pinning them.
	in = testInput()
	in.Tunnels = []TunnelInput{{Name: "infra", Iface: "utun6", Routes: []string{"198.51.100.0/24", "192.168.70.0/24"}, Servers: []netip.Addr{server}}}
	if got := tunnelRoutes(in); got != "192.168.70.0/24" {
		t.Errorf("via default: tunnel routes = %s, want only 192.168.70.0/24", got)
	}

	// Pinned (via: direct), or someone else's host route holds the server:
	// the more specific route keeps the connection out of the tunnel.
	in.Tunnels[0].Bypass = []netip.Addr{server}
	if got := tunnelRoutes(in); got != "192.168.70.0/24,198.51.100.0/24" {
		t.Errorf("pinned: tunnel routes = %s", got)
	}
	in.Tunnels[0].Bypass = nil
	in.Occupied = map[string]string{"198.51.100.7/32": "en0"}
	if got := tunnelRoutes(in); got != "192.168.70.0/24,198.51.100.0/24" {
		t.Errorf("held by another route: tunnel routes = %s", got)
	}
}
