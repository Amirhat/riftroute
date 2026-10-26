package routing

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

// fullDesired builds a desired set with a full tunnel ("all", utun7) and the
// given profiles, and indexes its routes by destination.
func fullDesired(t *testing.T, tun TunnelInput, profiles ...domain.Profile) (map[string]domain.ManagedRoute, []domain.ManagedRule, TunnelPlan) {
	t.Helper()
	in := testInput(profiles...)
	in.PhysNetV4 = netip.MustParsePrefix("192.168.1.0/24")
	in.Tunnels = []TunnelInput{tun}
	desired, rules, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	oneRoutePerDestination(t, desired)
	by := map[string]domain.ManagedRoute{}
	for _, d := range desired {
		by[d.DstCIDR] = d
	}
	return by, rules, PlanTunnels(in)
}

// A full tunnel takes the quarters of both families, whole; what's routed
// more specifically keeps its path — an exclude profile's routes stay (they
// don't yield to the quarters as they would to a tunnel's networks), and the
// server stays pinned to the router. Nothing is carved: a piece of a quarter
// would outrank the routes inside it.
func TestFullTunnelCarriesTheRest(t *testing.T) {
	excl := domain.Profile{ID: "exc", Name: "exc", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "9.9.9.0/24"}, {Type: domain.RuleIP, Value: "1.1.1.1"}}}
	server := netip.MustParseAddr("198.51.100.7")
	by, _, _ := fullDesired(t, TunnelInput{Name: "all", Iface: "utun7", V6: true, AllTraffic: true, Bypass: []netip.Addr{server}}, excl)

	for _, q := range FullTunnelQuarters {
		if r, ok := by[q]; !ok || r.Iface != "utun7" || r.Reject || r.ProfileID != "tunnel:all" {
			t.Errorf("quarter %s: %+v (present %v)", q, r, ok)
		}
	}
	for dst, r := range by {
		if r.Iface == "utun7" && netip.MustParsePrefix(dst).Bits() != 2 {
			t.Errorf("a piece %s went into the tunnel", dst)
		}
	}
	for _, p := range []string{"9.9.9.0/24", "1.1.1.1/32"} {
		if r, ok := by[p]; !ok || r.Gateway != "192.168.1.1" || r.Iface != "en0" {
			t.Errorf("exclude route %s yielded to the full tunnel: %+v (present %v)", p, r, ok)
		}
	}
	if r := by["198.51.100.7/32"]; r.Gateway != "192.168.1.1" {
		t.Errorf("the server isn't pinned to the router: %+v", r)
	}
}

// What a full tunnel mustn't carry, and nothing narrower already routes, is
// pinned along its usual path — the main VPN's default here — instead of
// carved: an exclude profile for 10.0.0.0/8 keeps all of it, the main VPN's
// DNS server (inside its own 10.8.0.0/24) needs nothing, and an anchor and a
// via-default server go by the main VPN.
func TestFullTunnelPinsInsteadOfCarving(t *testing.T) {
	excl := domain.Profile{ID: "exc", Name: "exc", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.0.0.0/8"}}}
	in := testInput(excl)
	in.PhysNetV4 = netip.MustParsePrefix("192.168.1.0/24")
	in.VPNIfaceV4, in.VPNGatewayV4 = "utun3", netip.MustParseAddr("10.8.0.1") // the main VPN's default
	in.Occupied = map[string]string{"10.8.0.0/24": "utun3", "0.0.0.0/1": "utun3", "128.0.0.0/1": "utun3"}
	in.DNSServers = []netip.Addr{netip.MustParseAddr("10.8.0.1")}
	in.Anchors = []netip.Addr{netip.MustParseAddr("1.0.0.1")}
	in.Tunnels = []TunnelInput{{Name: "all", Iface: "utun7", AllTraffic: true, Servers: []netip.Addr{netip.MustParseAddr("203.0.113.9")}}}
	desired, _, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	oneRoutePerDestination(t, desired)
	by := map[string]domain.ManagedRoute{}
	for _, d := range desired {
		by[d.DstCIDR] = d
		if p := netip.MustParsePrefix(d.DstCIDR); d.Iface == "utun7" && p.Bits() > 8 && netip.MustParsePrefix("10.0.0.0/8").Overlaps(p) {
			t.Errorf("%s into the tunnel outranks the exclude route for 10.0.0.0/8", p)
		}
	}
	if r := by["10.0.0.0/8"]; r.Gateway != "192.168.1.1" {
		t.Errorf("the exclude route: %+v", r)
	}
	for _, a := range []string{"1.0.0.1/32", "203.0.113.9/32"} {
		if r, ok := by[a]; !ok || r.Iface != "utun3" || r.Gateway != "" {
			t.Errorf("%s isn't pinned on-link into the main VPN: %+v (present %v)", a, r, ok)
		}
	}
	if _, ok := by["10.8.0.1/32"]; ok {
		t.Error("the main VPN's DNS server was pinned, though its own network already routes it")
	}
	nw := PlanTunnels(in).Narrowed["all"]
	if len(nw) != 1 || nw[0].Route != "all traffic" || len(nw[0].Except) != 2 {
		t.Errorf("narrowed: %+v", nw)
	}
}

// Without IPv6 on the tunnel, its v6 quarters are refused while it's up, so
// IPv6 doesn't go around it; v4 goes in.
func TestFullTunnelBlocksIPv6ItCantCarry(t *testing.T) {
	by, _, tp := fullDesired(t, TunnelInput{Name: "all", Iface: "utun7", AllTraffic: true})
	for _, q := range []string{"::/2", "4000::/2", "8000::/2", "c000::/2"} {
		if r, ok := by[q]; !ok || !r.Reject {
			t.Errorf("v6 quarter %s isn't refused: %+v (present %v)", q, r, ok)
		}
	}
	if r := by["0.0.0.0/2"]; r.Iface != "utun7" || r.Reject {
		t.Errorf("v4 quarter: %+v", r)
	}
	if b := tp.Blocked["all"]; len(b) != 1 || b[0].Route != "IPv6" || !strings.Contains(b[0].Reason, "IPv6 is blocked") {
		t.Errorf("blocked: %+v", b)
	}
}

// Include profiles keep their path past a full tunnel: their rules aren't cut
// around the quarters, as they are around a tunnel's own networks.
func TestFullTunnelLeavesIncludeRules(t *testing.T) {
	inc := domain.Profile{ID: "inc", Name: "inc", Enabled: true, Mode: domain.ModeInclude,
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.0.0.0/8"}}}
	in := testInput(inc)
	in.PolicyRouting, in.VPNIfaceV4 = true, "tun0"
	in.Tunnels = []TunnelInput{{Name: "all", Iface: "utun7", AllTraffic: true}}
	_, rules, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rules {
		found = found || r.Selector == "to 10.0.0.0/8"
	}
	if !found {
		t.Fatalf("the include rule was cut around the full tunnel: %+v", rules)
	}
}

// Down: its quarters go (traffic takes its usual path) — or, set to block,
// they're refused, so only what's routed more specifically goes anywhere.
func TestFullTunnelWhenDown(t *testing.T) {
	by, _, _ := fullDesired(t, TunnelInput{Name: "all", AllTraffic: true})
	if _, ok := by["0.0.0.0/2"]; ok {
		t.Error("a down full tunnel kept its quarters")
	}
	by, _, _ = fullDesired(t, TunnelInput{Name: "all", AllTraffic: true, Block: true, Servers: []netip.Addr{netip.MustParseAddr("198.51.100.7")}})
	for _, q := range []string{"0.0.0.0/2", "64.0.0.0/2", "::/2"} {
		if r, ok := by[q]; !ok || !r.Reject {
			t.Errorf("block when down: %s isn't refused: %+v (present %v)", q, r, ok)
		}
	}
	// Its server stays reachable, to connect again: pinned past the refusal.
	if r, ok := by["198.51.100.7/32"]; !ok || r.Reject || r.Gateway != "192.168.1.1" {
		t.Errorf("the server isn't pinned past the refused quarter: %+v (present %v)", r, ok)
	}
}

// Two full tunnels can't both take everything: the second's quarters are
// left out, with the reason.
func TestTwoFullTunnels(t *testing.T) {
	in := testInput()
	in.Tunnels = []TunnelInput{
		{Name: "b", Iface: "utun8", AllTraffic: true},
		{Name: "a", Iface: "utun7", AllTraffic: true},
	}
	desired, _, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	oneRoutePerDestination(t, desired)
	for _, d := range desired {
		if d.DstCIDR == "0.0.0.0/2" && d.Iface != "utun7" {
			t.Errorf("0.0.0.0/2 went to %s, want tunnel a's", d.Iface)
		}
	}
	blocked := PlanTunnels(in).Blocked["b"]
	if len(blocked) == 0 || !strings.Contains(blocked[0].Reason, "tunnel a") {
		t.Fatalf("b's quarters: %+v", blocked)
	}
}

// Beside Tailscale's exit node (Linux), a full tunnel's quarters are copied
// past it — and main is looked up first, all but /2 and wider, so the LAN's
// connected route (the router, a DNS server on it) keeps beating a quarter's
// copy, up or blocking. A tunnel that lists networks needs no such rule.
func TestFullTunnelBesideAnExitNodeKeepsTheLAN(t *testing.T) {
	rule := func(rules []domain.ManagedRule) (n int) {
		for _, r := range rules {
			if r.Priority == FullTunnelMainRulePrio && r.Table == "main" && r.Selector == "from all suppress_prefixlength 2" {
				n++
			}
		}
		return n
	}
	for _, tc := range []struct {
		name string
		tun  TunnelInput
		want int
	}{
		{"up, v4 and v6", TunnelInput{Name: "all", Iface: "utun7", V6: true, AllTraffic: true}, 2},
		{"blocking", TunnelInput{Name: "all", AllTraffic: true, Block: true}, 2},
		{"lists networks", TunnelInput{Name: "lab", Iface: "utun7", Routes: []string{"10.20.0.0/16"}}, 0},
	} {
		in := testInput()
		in.Tunnels = []TunnelInput{tc.tun}
		in.Tailscale, in.TailscaleTable, in.TailscaleExitNode = tailnet(), "52", true
		_, rules, err := BuildDesired(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := rule(rules); got != tc.want {
			t.Errorf("%s: %d main-before-copies rules, want %d", tc.name, got, tc.want)
		}
		// Gone with the exit node: the copies and this rule together.
		in.TailscaleExitNode = false
		if _, rules, _ = BuildDesired(in); rule(rules) != 0 {
			t.Errorf("%s: the rule stayed without the exit node", tc.name)
		}
	}
}

// The DNS servers the system resolves with through a full tunnel go into it,
// even one the watchdog probes too: never pinned out.
func TestFullTunnelKeepsItsDNSIn(t *testing.T) {
	in := testInput()
	in.Anchors = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")}
	in.Tunnels = []TunnelInput{{Name: "all", Iface: "utun7", AllTraffic: true, DNS: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}}
	desired, _, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]domain.ManagedRoute{}
	for _, d := range desired {
		by[d.DstCIDR] = d
	}
	if r := by["1.1.1.1/32"]; r.Iface != "utun7" {
		t.Errorf("the tunnel's DNS server pinned out: %+v", r)
	}
	if r, ok := by["1.0.0.1/32"]; !ok || r.Iface == "utun7" {
		t.Errorf("the other anchor isn't pinned out: %+v", r)
	}
}

// While it's up, its DNS servers go in by host routes of their own, so a
// narrower route — an exclude profile's network, another VPN's — doesn't
// take them. Not one on the LAN, a tunnel's server or IPv6 it can't carry;
// and an exclude profile's own route for that very host still wins.
func TestFullTunnelRoutesItsDNSIn(t *testing.T) {
	excl := domain.Profile{ID: "exc", Name: "exc", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "9.9.9.0/24"}, {Type: domain.RuleIP, Value: "8.8.4.4"}}}
	in := testInput(excl)
	in.PhysNetV4 = netip.MustParsePrefix("192.168.1.0/24")
	in.Occupied = map[string]string{"10.0.0.0/8": "utun3"}
	server := netip.MustParseAddr("198.51.100.7")
	var dns []netip.Addr
	for _, a := range []string{"9.9.9.9", "10.10.0.53", "192.168.1.1", "198.51.100.7", "8.8.4.4", "2001:db8::53"} {
		dns = append(dns, netip.MustParseAddr(a))
	}
	in.Tunnels = []TunnelInput{{Name: "all", Iface: "utun7", AllTraffic: true, Bypass: []netip.Addr{server}, DNS: dns}}
	desired, _, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	oneRoutePerDestination(t, desired)
	by := map[string]domain.ManagedRoute{}
	for _, d := range desired {
		by[d.DstCIDR] = d
	}
	for _, h := range []string{"9.9.9.9/32", "10.10.0.53/32"} {
		if r := by[h]; r.Iface != "utun7" || r.Gateway != "" {
			t.Errorf("%s not routed into the tunnel: %+v", h, r)
		}
	}
	if r, ok := by["192.168.1.1/32"]; ok {
		t.Errorf("the router routed: %+v", r)
	}
	if r := by["198.51.100.7/32"]; r.Iface == "utun7" {
		t.Errorf("the tunnel's server routed into it: %+v", r)
	}
	if r := by["8.8.4.4/32"]; r.Iface == "utun7" || r.Profile != "exc" {
		t.Errorf("the exclude profile's host route lost: %+v", r)
	}
	if r, ok := by["2001:db8::53/128"]; ok {
		t.Errorf("IPv6 it can't carry routed: %+v", r)
	}
}
