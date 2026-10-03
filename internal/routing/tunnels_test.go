package routing

import (
	"errors"
	"net/netip"
	"slices"
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
// server off the tunnel (via: default pins nothing; a pin can be lost) would
// send openvpn's packets into its own tunnel: it could never reconnect. The
// server is kept out of the route, the rest goes in.
func TestTunnelRouteContainingItsOwnServerKeepsItOut(t *testing.T) {
	server := netip.MustParseAddr("198.51.100.7")
	check := func(name string, in DesiredInput, wantKept bool) {
		t.Helper()
		desired, _, err := BuildDesired(in)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, d := range desired {
			p := netip.MustParsePrefix(d.DstCIDR)
			if d.Gateway != "" {
				continue // the pin
			}
			if p.Contains(server) {
				t.Errorf("%s: %s carries the server", name, p)
			}
			if netip.MustParsePrefix("198.51.100.0/24").Contains(p.Addr()) {
				n += 1 << (32 - p.Bits())
			}
		}
		if n != 255 {
			t.Errorf("%s: %d of the /24's other addresses go in", name, n)
		}
		nw := PlanTunnels(in).Narrowed["infra"]
		if kept := len(nw) == 1 && strings.Contains(nw[0].Except[0].Reason, "own server 198.51.100.7"); kept != wantKept {
			t.Errorf("%s: narrowed %+v", name, nw)
		}
	}

	// via: direct, but the pin can't be made (no physical gateway for it).
	in := testInput()
	in.GatewayV4 = netip.Addr{}
	in.Tunnels = []TunnelInput{{Name: "infra", Iface: "utun6", Routes: []string{"198.51.100.0/24", "192.168.70.0/24"}, Bypass: []netip.Addr{server}}}
	check("unpinned", in, true)

	// via: default — the manager reports the servers without pinning them.
	in = testInput()
	in.Tunnels = []TunnelInput{{Name: "infra", Iface: "utun6", Routes: []string{"198.51.100.0/24", "192.168.70.0/24"}, Servers: []netip.Addr{server}}}
	check("via default", in, true)

	// Pinned (via: direct), or someone else's host route holds the server:
	// the more specific route keeps the connection out of the tunnel, and
	// the /24 goes in whole.
	in.Tunnels[0].Bypass = []netip.Addr{server}
	if got := strings.Join(tunnelDsts(t, in), ","); got != "192.168.70.0/24,198.51.100.0/24" {
		t.Errorf("pinned: tunnel routes = %s", got)
	}
	in.Tunnels[0].Bypass = nil
	in.Occupied = map[string]string{"198.51.100.7/32": "en0"}
	if got := strings.Join(tunnelDsts(t, in), ","); got != "192.168.70.0/24,198.51.100.0/24" {
		t.Errorf("held by another route: tunnel routes = %s", got)
	}
}

// tunnelDsts are the routes into tunnels (no pins), sorted.
func tunnelDsts(t *testing.T, in DesiredInput) []string {
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
	slices.Sort(out)
	return out
}

// A route matches its own table entry whichever way its gateway is spelled:
// recorded as `route get` prints it, listed by the RIB without the zone or
// with the scope embedded (KAME).
func TestKernelKeyMatchesAGatewaysSpellings(t *testing.T) {
	r := func(gw, iface string) domain.Route {
		return domain.Route{DstCIDR: "2001:db8::7/128", Gateway: gw, Iface: iface, Family: domain.FamilyV6}
	}
	rec := KernelKey(r("fe80::1%en0", "en0"))
	for _, listed := range []string{"fe80::1", "fe80:4::1", "fe80::1%en0"} {
		if got := KernelKey(r(listed, "en0")); got != rec {
			t.Errorf("%s: %q != %q", listed, got, rec)
		}
	}
	for _, other := range []domain.Route{r("fe80::2", "en0"), r("fe80::1", "en7"), r("", "en0")} {
		if KernelKey(other) == rec {
			t.Errorf("%+v matches the recorded route", other)
		}
	}
}

// Two via-default tunnels each listing the network behind the other's server
// would carry each other's connections and both stall: each keeps the
// other's server out.
func TestTunnelsNeverCarryEachOthersServer(t *testing.T) {
	in := testInput()
	in.Tunnels = []TunnelInput{
		{Name: "a", Iface: "utun8", Routes: []string{"10.0.0.0/16"}, Servers: []netip.Addr{netip.MustParseAddr("172.16.1.1")}},
		{Name: "b", Iface: "utun9", Routes: []string{"172.16.0.0/16"}, Servers: []netip.Addr{netip.MustParseAddr("10.0.5.5")}},
	}
	tp := PlanTunnels(in)
	for name, other := range map[string]string{"a": "b", "b": "a"} {
		n := tp.Narrowed[name]
		if len(tp.Blocked[name]) != 0 || len(n) != 1 || !strings.Contains(n[0].Except[0].Reason, "tunnel "+other+"'s server") {
			t.Errorf("%s: narrowed %+v, blocked %+v", name, n, tp.Blocked[name])
		}
	}
	for _, r := range tp.Routes {
		p := netip.MustParsePrefix(r.DstCIDR)
		if p.Contains(netip.MustParseAddr("172.16.1.1")) || p.Contains(netip.MustParseAddr("10.0.5.5")) {
			t.Errorf("%s (%s) carries a tunnel's server", p, r.ProfileID)
		}
	}
	// A pinned server (via direct) is held off every tunnel: no conflict.
	in.Tunnels[1].Bypass = in.Tunnels[1].Servers
	if bs := PlanTunnels(in).Narrowed["a"]; len(bs) != 0 {
		t.Errorf("a pinned server still kept out: %+v", bs)
	}
}

// VerifyRoutes leaves out what desired still wants and the kernel no longer
// holds — any route, not only a tunnel's — so a reconcile puts it back. It
// keeps what's held (never a tunnel's), what desired no longer wants (so the
// plan's delete clears it), what another route's destination now covers
// (Taken), and everything when the table can't be read; only limits it.
func TestVerifyRoutes(t *testing.T) {
	excl := domain.ManagedRoute{Route: domain.Route{DstCIDR: "9.9.9.0/24", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4}, ProfileID: "p1"}
	tun := domain.ManagedRoute{Route: domain.Route{DstCIDR: "10.20.0.0/16", Iface: "utun6", Family: domain.FamilyV4}, ProfileID: TunnelProfilePrefix + "lab"}
	block := domain.ManagedRoute{Route: domain.Route{DstCIDR: "10.30.0.0/16", Reject: true, Family: domain.FamilyV4}, ProfileID: TunnelProfilePrefix + "office"}
	stale := domain.ManagedRoute{Route: domain.Route{DstCIDR: "8.8.8.8/32", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4}, ProfileID: "p1"}
	owned := []domain.ManagedRoute{excl, tun, block, stale}
	desired := []domain.ManagedRoute{excl, tun, block} // stale: no longer wanted
	empty := func(domain.Family) ([]domain.Route, error) { return nil, nil }
	keys := func(ms []domain.ManagedRoute) string {
		var out []string
		for _, m := range ms {
			out = append(out, m.DstCIDR)
		}
		return strings.Join(out, ",")
	}

	v := VerifyRoutes(owned, desired, empty, nil, nil)
	if keys(v.Missing) != "9.9.9.0/24,10.20.0.0/16,10.30.0.0/16" || keys(v.Kept) != "8.8.8.8/32" {
		t.Fatalf("kept %s, missing %s", keys(v.Kept), keys(v.Missing))
	}
	allHeld := map[string]bool{RouteKey(excl.Route): true, RouteKey(tun.Route): true, RouteKey(block.Route): true}
	if v = VerifyRoutes(owned, desired, empty, allHeld, nil); keys(v.Missing) != "10.20.0.0/16,10.30.0.0/16" {
		t.Fatalf("held: missing %s, want the tunnel's never held", keys(v.Missing))
	}
	if v = VerifyRoutes(owned, desired, empty, nil, IsTunnelRoute); keys(v.Missing) != "10.20.0.0/16,10.30.0.0/16" {
		t.Fatalf("tunnels only: missing %s", keys(v.Missing))
	}
	there := func(domain.Family) ([]domain.Route, error) {
		return []domain.Route{excl.Route, tun.Route, block.Route}, nil
	}
	if v = VerifyRoutes(owned, desired, there, nil, nil); len(v.Missing) != 0 || len(v.Kept) != 4 {
		t.Fatalf("all there: kept %s, missing %s", keys(v.Kept), keys(v.Missing))
	}
	other := func(domain.Family) ([]domain.Route, error) { // another program's route to our destination
		return []domain.Route{{DstCIDR: "9.9.9.0/24", Iface: "utun3", Family: domain.FamilyV4}, tun.Route, block.Route}, nil
	}
	if v = VerifyRoutes(owned, desired, other, nil, nil); len(v.Missing) != 0 || keys(v.Taken) != "9.9.9.0/24" || len(v.Kept) != 4 {
		t.Fatalf("taken: kept %s, missing %s, taken %s", keys(v.Kept), keys(v.Missing), keys(v.Taken))
	}
	failed := func(domain.Family) ([]domain.Route, error) { return nil, errors.New("read failed") }
	if v = VerifyRoutes(owned, desired, failed, nil, nil); len(v.Missing) != 0 || len(v.Kept) != 4 {
		t.Fatal("a failed read changed the records")
	}
}
