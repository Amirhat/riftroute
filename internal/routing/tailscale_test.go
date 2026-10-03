package routing

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

// tailnet is a Tailscale beside us, as tailscale.Detect gives it.
func tailnet() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48"), netip.MustParsePrefix("10.20.0.0/16")}
}

// What a Tailscale beside us routes stays its own: exclude destinations
// inside its networks yield, and (Linux) its table is looked up before
// RiftRoute's rules — one rule a family, all but its default — so include
// rules and marked apps can't take them. macOS cuts include rules instead.
func TestProfilesLeaveTailscalesNetworksToIt(t *testing.T) {
	inc := domain.Profile{ID: "inc", Name: "inc", Enabled: true, Mode: domain.ModeInclude, Rules: []domain.Rule{
		{Type: domain.RuleCIDR, Value: "10.0.0.0/8"}, {Type: domain.RuleCIDR, Value: "100.0.0.0/8"}, {Type: domain.RuleApp, Value: "/user.slice/x"},
	}}
	exc := domain.Profile{ID: "exc", Name: "exc", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto", Rules: []domain.Rule{
		{Type: domain.RuleIP, Value: "100.101.1.2"}, {Type: domain.RuleIP, Value: "8.8.8.8"},
	}}
	in := testInput(inc, exc)
	in.PolicyRouting, in.VPNIfaceV4 = true, "tun0"
	in.Tailscale, in.TailscaleTable = tailnet(), "52"
	routes, rules, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		if r.DstCIDR == "100.101.1.2/32" {
			t.Errorf("an exclude route took a tailnet address: %+v", r)
		}
	}
	var toTS []string
	for _, r := range rules {
		if r.Table == "52" {
			if r.Priority != TailscaleRulePrio || r.Selector != "from all suppress_prefixlength 0" {
				t.Errorf("Tailscale's rule %+v", r)
			}
			toTS = append(toTS, string(r.Family))
		}
	}
	if strings.Join(toTS, ",") != string(domain.FamilyV4)+","+string(domain.FamilyV6) {
		t.Errorf("rules to Tailscale's table, by family: %v", toTS)
	}

	// macOS has no tables: no such rule, and include rules are cut instead.
	in.Platform = "darwin"
	_, rules, _ = BuildDesired(in)
	for _, r := range rules {
		if r.Table == "52" {
			t.Errorf("a table-52 rule on macOS: %+v", r)
		}
		for _, f := range strings.Fields(r.Selector) {
			if p, err := netip.ParsePrefix(f); err == nil {
				for _, n := range tailnet() {
					if p.Overlaps(n) {
						t.Errorf("include rule %s takes Tailscale's %s", p, n)
					}
				}
			}
		}
	}
}

// With Tailscale's exit node on (Linux), its rule sends everything to its
// table before main: RiftRoute's main-table routes are copied into a table
// looked up first — after Tailscale's own networks, so the copies are plain
// — and the copies go when the exit node does.
func TestRoutesAreMirroredPastAnExitNode(t *testing.T) {
	exc := domain.Profile{ID: "exc", Name: "exc", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto", Rules: []domain.Rule{
		{Type: domain.RuleCIDR, Value: "10.0.0.0/8"}, {Type: domain.RuleIP, Value: "8.8.8.8"},
	}}
	in := testInput(exc)
	in.Tailscale, in.TailscaleTable, in.TailscaleExitNode = tailnet(), "52", true
	routes, rules, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	main, copies := map[string]bool{}, 0
	for _, r := range routes {
		switch r.Table {
		case "":
			main[r.DstCIDR] = true
		case BypassTable:
			copies++
			if r.Gateway != "192.168.1.1" {
				t.Errorf("a copy with another next hop: %+v", r)
			}
		}
	}
	if !main["10.0.0.0/8"] || !main["8.8.8.8/32"] || copies != len(main) {
		t.Fatalf("main %v, %d copies", main, copies)
	}
	var bypass []domain.ManagedRule
	for _, r := range rules {
		if r.Table == BypassTable {
			bypass = append(bypass, r)
		}
		if r.Table == "52" && r.Priority >= BypassRulePrio {
			t.Errorf("Tailscale's networks looked up after the copies: %+v", r)
		}
	}
	if len(bypass) != 1 || bypass[0].Priority != BypassRulePrio || bypass[0].Selector != "from all" || bypass[0].Family != domain.FamilyV4 {
		t.Fatalf("bypass rules %+v", bypass)
	}

	// No exit node, or macOS: no copies — and a set that held some loses them.
	in.TailscaleExitNode = false
	r2, rules2 := BesideTailscale(routes, rules, in)
	for _, r := range r2 {
		if r.Table == BypassTable {
			t.Fatalf("a copy without the exit node: %+v", r)
		}
	}
	for _, r := range rules2 {
		if r.Table == BypassTable {
			t.Fatalf("the bypass rule without the exit node: %+v", r)
		}
	}
	in.TailscaleExitNode, in.Platform = true, "darwin"
	if r3, _ := BesideTailscale(r2, rules2, in); len(r3) != len(r2) {
		t.Fatal("copies on macOS")
	}
}

// A tunnel apply builds on the rules in the kernel, which may lack
// Tailscale's lookup rule (Tailscale came up since the last full apply):
// copies never go in without it ahead of them, and both go with Tailscale.
func TestCopiesNeverGoInWithoutTailscalesRuleAhead(t *testing.T) {
	in := testInput()
	in.Tailscale, in.TailscaleTable, in.TailscaleExitNode = tailnet(), "52", true
	routes := []domain.ManagedRoute{{Route: domain.Route{DstCIDR: "10.0.0.0/8", Iface: "utun6", Family: domain.FamilyV4}, ProfileID: "tunnel:infra"}}
	r, rules := BesideTailscale(routes, nil, in)
	ahead := false
	for _, x := range rules {
		if x.Table == "52" && x.Priority == TailscaleRulePrio && x.Priority < BypassRulePrio && x.Family == domain.FamilyV4 {
			ahead = true
		}
	}
	if len(r) != 2 || !ahead {
		t.Fatalf("routes %+v, rules %+v", r, rules)
	}
	in.Tailscale, in.TailscaleTable, in.TailscaleExitNode = nil, "", false
	r, rules = BesideTailscale(r, rules, in)
	if len(r) != 1 || len(rules) != 0 {
		t.Fatalf("with Tailscale gone: routes %+v, rules %+v", r, rules)
	}
	// macOS's pass at the same priority (no table) is the include rules',
	// not ours to drop.
	pass := domain.ManagedRule{PolicyRule: domain.PolicyRule{Priority: TailscaleRulePrio, Selector: "to 100.64.0.0/10 user 501"}}
	in.Platform = "darwin"
	if _, rules = BesideTailscale(nil, []domain.ManagedRule{pass}, in); len(rules) != 1 {
		t.Fatal("dropped macOS's pass")
	}
}

// A tunnel route inside what Tailscale routes is left to it, with the reason
// (on macOS the narrower route would otherwise win over its range). A wider
// one is installed: Tailscale's narrower routes keep winning inside it.
func TestTunnelRoutesInsideTailscaleAreLeftToIt(t *testing.T) {
	in := testInput()
	in.Tailscale = tailnet()
	in.Occupied = map[string]string{}
	for _, n := range tailnet() {
		in.Occupied[n.String()] = "tailscale0 (Tailscale)"
	}
	in.Tunnels = []TunnelInput{{Name: "infra", Iface: "utun6", V6: true, Routes: []string{"100.70.0.0/16", "10.20.5.0/24", "fd7a:115c:a1e0:ab::/64", "10.0.0.0/8", "10.30.0.0/16"}}}
	var left []string
	for _, b := range PlanTunnels(in).Blocked["infra"] {
		if !strings.Contains(b.Reason, "Tailscale") {
			t.Errorf("%s left out for %q", b.Route, b.Reason)
		}
		left = append(left, b.Route)
	}
	if strings.Join(left, ",") != "100.70.0.0/16,10.20.5.0/24,fd7a:115c:a1e0:ab::/64" {
		t.Errorf("left to Tailscale: %v", left)
	}
	desired, _, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	oneRoutePerDestination(t, desired)
	got := map[string]bool{}
	for _, d := range desired {
		if d.Iface != "utun6" {
			continue
		}
		got[d.DstCIDR] = true
		p := netip.MustParsePrefix(d.DstCIDR)
		for _, n := range tailnet() {
			if n.Bits() <= p.Bits() && n.Contains(p.Addr()) {
				t.Errorf("a tunnel route %s inside Tailscale's %s", p, n)
			}
		}
	}
	if !got["10.0.0.0/8"] { // 10.30.0.0/16 rides inside it
		t.Errorf("tunnel routes %v", got)
	}
}

// The plan preview's command for a rule names its family, as the provider
// runs it: a v6 "from all …" line copied without -6 lands on its v4 twin.
func TestRuleCommandCarriesTheFamily(t *testing.T) {
	v6 := domain.PolicyRule{Priority: TailscaleRulePrio, Selector: "from all suppress_prefixlength 0", Table: "52", Family: domain.FamilyV6}
	if got := strings.Join(commandForRule(domain.OpAddRule, v6), " "); !strings.HasPrefix(got, "ip -6 rule add from all suppress_prefixlength 0 lookup 52") {
		t.Fatalf("v6: %s", got)
	}
	old := domain.PolicyRule{Priority: 5252, Selector: "to fd00::/8", Table: "5252"} // recorded without a family
	if got := strings.Join(commandForRule(domain.OpDelRule, old), " "); !strings.HasPrefix(got, "ip -6 rule del to fd00::/8") {
		t.Fatalf("from the selector: %s", got)
	}
}
