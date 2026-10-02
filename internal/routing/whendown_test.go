package routing

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

// rejects returns the reject routes of a desired set, by destination, with
// the tag they carry.
func rejects(desired []domain.ManagedRoute) map[string]string {
	out := map[string]string{}
	for _, d := range desired {
		if d.Reject {
			out[d.DstCIDR] = d.ProfileID
		}
	}
	return out
}

// A tunnel set to block that's down (connecting, reconnecting, failed —
// Block, no interface): each of its destinations is refused, aggregated and
// tagged as the tunnel's, with no gateway or interface. The same tunnel
// without Block installs nothing while it's down.
func TestDownBlockTunnelRefusesItsDestinations(t *testing.T) {
	in := testInput()
	in.Tunnels = []TunnelInput{{Name: "con3", Block: true, Routes: []string{"9.9.9.9", "10.70.0.0/17", "10.70.128.0/17"}}}
	desired, _, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	oneRoutePerDestination(t, desired)
	got := rejects(desired)
	if len(got) != 2 || got["9.9.9.9/32"] != "tunnel:con3" || got["10.70.0.0/16"] != "tunnel:con3" {
		t.Fatalf("reject routes = %v (desired %+v)", got, desired)
	}
	for _, d := range desired {
		if d.Reject && (d.Gateway != "" || d.Iface != "" || d.Owner != domain.OwnerRiftRoute) {
			t.Errorf("a reject route with a next hop or not ours: %+v", d)
		}
	}

	in.Tunnels[0].Block = false
	if desired, _, err = BuildDesired(in); err != nil {
		t.Fatal(err)
	}
	if len(desired) != 0 {
		t.Fatalf("a down tunnel without Block installs nothing: %+v", desired)
	}
}

// A reject route goes through the same checks as a route into a tunnel:
// what it holds that would cut the connection (or the tunnel's own way
// back) — the router's network, a resolver, an anchor, a tunnel's server —
// is kept out of it, and the rest refused. A destination a live tunnel
// routes stays the live tunnel's.
func TestDownBlockTunnelKeepsOutWhatWouldCutTheConnection(t *testing.T) {
	in := testInput()
	in.PhysNetV4 = netip.MustParsePrefix("192.168.1.0/24")
	in.DNSServers = []netip.Addr{netip.MustParseAddr("10.255.255.1")}
	server := netip.MustParseAddr("203.0.113.9")
	in.Tunnels = []TunnelInput{
		{Name: "con3", Block: true, Servers: []netip.Addr{server},
			Routes: []string{"192.168.0.0/16", "10.255.0.0/16", "203.0.113.0/24", "172.16.5.0/24", "9.9.9.9"}},
		{Name: "live", Iface: "utun6", Routes: []string{"172.16.5.0/24"}},
	}
	desired, _, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	oneRoutePerDestination(t, desired)
	got := rejects(desired)
	if got["9.9.9.9/32"] == "" || got["192.168.0.0/24"] == "" {
		t.Fatalf("reject routes = %v", got)
	}
	for dst := range got {
		p := netip.MustParsePrefix(dst)
		for _, a := range []string{"192.168.1.1", "192.168.1.200", "10.255.255.1", "203.0.113.9", "172.16.5.1"} {
			if p.Contains(netip.MustParseAddr(a)) {
				t.Errorf("reject route %s refuses %s", p, a)
			}
		}
	}
	if byDestination(desired)["v4||172.16.5.0/24"][0].Iface != "utun6" {
		t.Errorf("the live tunnel lost its destination: %+v", desired)
	}
	tp := PlanTunnels(in)
	if bs := tp.Blocked["con3"]; len(bs) != 1 || bs[0].Route != "172.16.5.0/24" || !strings.Contains(bs[0].Reason, "tunnel live") {
		t.Errorf("blocked %+v", bs)
	}
	kept := map[string]string{}
	for _, n := range tp.Narrowed["con3"] {
		for _, e := range n.Except {
			kept[n.Route] += e.Reason
		}
	}
	for route, want := range map[string]string{
		"192.168.0.0/16": "the network of your router",
		"10.255.0.0/16":  "DNS server",
		"203.0.113.0/24": "own server",
	} {
		if !strings.Contains(kept[route], want) {
			t.Errorf("%s: kept out %q, want it to say %q", route, kept[route], want)
		}
	}
}

// Blocked destinations belong to the tunnel as its live routes do: an
// exclude route inside them yields (it'd carry the traffic out past the
// block), and an include rule — matched before the table — is cut around
// them, on Linux and macOS alike.
func TestBlockedDestinationsKeepExcludeAndIncludeOut(t *testing.T) {
	work := domain.Profile{
		ID: "work", Name: "WORK", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleIP, Value: "10.70.1.5"}, {Type: domain.RuleIP, Value: "8.8.8.8"}},
	}
	in := testInput(work)
	in.Tunnels = []TunnelInput{{Name: "con3", Block: true, Routes: []string{"10.70.0.0/16"}}}
	desired, _, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	got := byDestination(desired)
	if got["v4||10.70.1.5/32"] != nil {
		t.Error("10.70.1.5 is blocked with the tunnel; the exclude route must yield")
	}
	if got["v4||8.8.8.8/32"] == nil || got["v4||10.70.0.0/16"] == nil || !got["v4||10.70.0.0/16"][0].Reject {
		t.Errorf("desired = %+v", desired)
	}

	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			in := testInput(domain.Profile{
				ID: "p2", Name: "corp", Enabled: true, Mode: domain.ModeInclude,
				Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.0.0.0/8"}},
			})
			in.Platform, in.PolicyRouting = platform, true
			in.VPNGatewayV4, in.VPNIfaceV4 = netip.MustParseAddr("10.8.0.1"), "utun3"
			in.Tunnels = []TunnelInput{{Name: "con3", Block: true, Routes: []string{"10.70.0.0/16"}}}
			_, rules, err := BuildDesired(in)
			if err != nil {
				t.Fatal(err)
			}
			if sels := includeSelectors(t, rules, netip.MustParsePrefix("10.70.0.0/16")); len(sels) == 0 {
				t.Errorf("the rest of 10.0.0.0/8 lost its include rules: %+v", rules)
			}
		})
	}
}

// Up, a block-mode tunnel with no IPv6 refuses its v6 destinations rather
// than leaving them to go out another way (a name with both addresses would
// leak over v6); without Block they're left out, as before. Its v4 ones go
// into it.
func TestUpBlockTunnelRefusesV6ItCantCarry(t *testing.T) {
	in := testInput()
	in.GatewayV6, in.PhysIfaceV6 = netip.MustParseAddr("fe80::1"), "en0"
	in.Tunnels = []TunnelInput{{Name: "con3", Iface: "utun6", Block: true, Routes: []string{"9.9.9.9", "2620:fe::fe"}}}
	desired, _, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	got := byDestination(desired)
	if r := got["v4||9.9.9.9/32"]; r == nil || r[0].Iface != "utun6" || r[0].Reject {
		t.Errorf("v4 into the tunnel: %+v", desired)
	}
	if r := got["v6||2620:fe::fe/128"]; r == nil || !r[0].Reject {
		t.Errorf("v6 refused: %+v", desired)
	}
	if bs := PlanTunnels(in).Blocked["con3"]; len(bs) != 1 || !strings.Contains(bs[0].Reason, "refused") {
		t.Errorf("blocked = %+v", bs)
	}

	in.Tunnels[0].Block = false
	if desired, _, err = BuildDesired(in); err != nil {
		t.Fatal(err)
	}
	if byDestination(desired)["v6||2620:fe::fe/128"] != nil {
		t.Errorf("without Block, v6 is left out: %+v", desired)
	}
}

// Going from blocked to connected (and back) swaps one route for another on
// the same destination: delete first, since the kernel holds one route per
// destination and a provider takes "File exists" for success.
func TestRejectToLiveIsAReplacement(t *testing.T) {
	in := testInput()
	in.Tunnels = []TunnelInput{{Name: "con3", Block: true, Routes: []string{"9.9.9.9"}}}
	blocked, _, _ := BuildDesired(in)
	in.Tunnels[0].Iface = "utun6"
	live, _, _ := BuildDesired(in)
	for _, c := range []struct {
		name     string
		from, to []domain.ManagedRoute
	}{{"up", blocked, live}, {"down", live, blocked}} {
		plan := Reconcile(c.to, c.from, nil, nil, "darwin")
		if len(plan.Ops) != 2 || plan.Ops[0].Kind != domain.OpDelRoute || plan.Ops[1].Kind != domain.OpAddRoute {
			t.Fatalf("%s: ops = %+v", c.name, plan.Ops)
		}
		if RouteKey(plan.Ops[0].Route.Route) == RouteKey(plan.Ops[1].Route.Route) {
			t.Fatalf("%s: a reject route and a live one share a key", c.name)
		}
	}
	add := Reconcile(blocked, nil, nil, nil, "darwin").Ops[0]
	if strings.Join(add.Command, " ") != "route -n add -host 9.9.9.9/32 127.0.0.1 -reject" || add.Human != "add 9.9.9.9/32 reject" {
		t.Errorf("darwin add = %q / %q", add.Command, add.Human)
	}
	if cmd := Reconcile(blocked, nil, nil, nil, "linux").Ops[0].Command; strings.Join(cmd, " ") != "ip route add unreachable 9.9.9.9/32 proto riftroute" {
		t.Errorf("linux add = %q", cmd)
	}
}

// A reject route is told apart from a route into a tunnel for the same
// destination: in the kernel check, the kernel key, and the lookup.
func TestRejectRouteIdentity(t *testing.T) {
	reject := domain.Route{DstCIDR: "9.9.9.9/32", Family: domain.FamilyV4, Reject: true}
	live := domain.Route{DstCIDR: "9.9.9.9/32", Iface: "utun6", Family: domain.FamilyV4}
	in := IndexInstalled([]domain.Route{reject})
	if !in.Has(reject) || in.Has(live) {
		t.Errorf("installed: reject %v, live %v", in.Has(reject), in.Has(live))
	}
	if IndexInstalled([]domain.Route{live}).Has(reject) {
		t.Error("a live route counted as the reject route")
	}
	if KernelKey(reject) == KernelKey(live) || RouteKey(reject) == RouteKey(live) {
		t.Error("keys collide")
	}

	reject.Profile = "tunnel:con3"
	d := Simulate([]domain.Route{{DstCIDR: "0.0.0.0/0", Gateway: "192.168.1.1", Iface: "en0"}, reject}, netip.MustParseAddr("9.9.9.9"), nil)
	if d.Reachable || !d.Rejected || d.Profile != "tunnel:con3" || d.MatchedCIDR != "9.9.9.9/32" {
		t.Errorf("simulated = %+v", d)
	}
	if !Drift(domain.RouteDecision{Reachable: false}, d) {
		t.Error("unreachable vs rejected is drift")
	}
	if Drift(domain.RouteDecision{Rejected: true}, d) {
		t.Error("both rejected isn't drift")
	}
}
