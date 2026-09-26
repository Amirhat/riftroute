package routing

import (
	"net/netip"
	"sort"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

// includeSelectors returns the destinations of the "to" rules, sorted, and
// fails on one that overlaps net.
func includeSelectors(t *testing.T, rules []domain.ManagedRule, net netip.Prefix) []string {
	t.Helper()
	var out []string
	for _, r := range rules {
		dst, ok := strings.CutPrefix(r.Selector, "to ")
		if !ok {
			continue
		}
		p := netip.MustParsePrefix(dst)
		if p.Overlaps(net) {
			t.Errorf("include rule %q still captures the tunnel's %s", r.Selector, net)
		}
		out = append(out, dst)
	}
	sort.Strings(out)
	return out
}

// An include rule is matched before the routing table: even a rule merely
// containing a live tunnel's network would capture its traffic into the VPN,
// where an exclude route loses to the tunnel's more specific route. So
// include destinations yield to live tunnels' networks — dropped inside them,
// cut around them — on Linux (Model B) and macOS (PF route-to) alike; a
// tunnel that isn't up takes nothing.
func TestIncludeRulesYieldToLiveTunnelNetworks(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			in := testInput(domain.Profile{
				ID: "p2", Name: "corp", Enabled: true, Mode: domain.ModeInclude,
				Rules: []domain.Rule{
					{Type: domain.RuleCIDR, Value: "10.0.0.0/8"},
					{Type: domain.RuleCIDR, Value: "10.70.1.0/24"},
					{Type: domain.RuleCIDR, Value: "172.16.0.0/12"},
				},
			})
			in.Platform = platform
			in.PolicyRouting = true
			in.VPNGatewayV4, in.VPNIfaceV4 = netip.MustParseAddr("10.8.0.1"), "utun3"
			tunnelNet := netip.MustParsePrefix("10.70.0.0/16")

			in.Tunnels = []TunnelInput{{Name: "infra", Routes: []string{"10.70.0.0/16"}}} // connecting
			_, rules, err := BuildDesired(in)
			if err != nil {
				t.Fatal(err)
			}
			var sels []string
			for _, r := range rules {
				sels = append(sels, r.Selector)
			}
			if strings.Join(sels, ",") != "to 10.0.0.0/8,to 172.16.0.0/12" {
				t.Fatalf("the tunnel isn't up; the include rules stay: %v", sels)
			}

			in.Tunnels[0].Iface = "utun6" // connected
			routes, rules, err := BuildDesired(in)
			if err != nil {
				t.Fatal(err)
			}
			got := includeSelectors(t, rules, tunnelNet)
			want := []string{"10.0.0.0/10", "10.128.0.0/9", "10.64.0.0/14", "10.68.0.0/15", "10.71.0.0/16", "10.72.0.0/13", "10.80.0.0/12", "10.96.0.0/11", "172.16.0.0/12"}
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("include destinations = %v\nwant %v", got, want)
			}
			if byDestination(routes)["v4||10.70.0.0/16"] == nil {
				t.Errorf("the tunnel's route is missing: %+v", routes)
			}
		})
	}
}

// The tunnel-only apply carries the installed rules over, placed as a full
// apply would place them: destination rules yield to the live tunnels'
// networks; an app's rule is kept as it is.
func TestRulesBesideYieldsToLiveTunnelNetworks(t *testing.T) {
	in := testInput()
	in.Tunnels = []TunnelInput{{Name: "infra", Iface: "utun6", Routes: []string{"10.70.0.0/16"}}}
	rule := func(sel string) domain.ManagedRule {
		return domain.ManagedRule{PolicyRule: domain.PolicyRule{Priority: ModelBRulePrio, Selector: sel, Table: ModelBTable, Family: domain.FamilyV4, Proto: "riftroute"}}
	}
	installed := []domain.ManagedRule{rule("to 10.0.0.0/8"), rule("to 10.70.1.0/24"), rule("from all fwmark 0x5252"), rule("to 172.16.0.0/12")}
	out := PlanTunnels(in).RulesBeside(installed)
	got := includeSelectors(t, out, netip.MustParsePrefix("10.70.0.0/16"))
	if len(got) != 9 || got[len(got)-1] != "172.16.0.0/12" {
		t.Errorf("destinations = %v", got)
	}
	fw := 0
	for _, r := range out {
		if r.Selector == "from all fwmark 0x5252" && r.Table == ModelBTable {
			fw++
		}
	}
	if fw != 1 {
		t.Errorf("the app rule must be kept as it is: %+v", out)
	}
	if again := PlanTunnels(testInput()).RulesBeside(installed); len(again) != len(installed) {
		t.Errorf("no live tunnel: rules = %+v", again)
	}
}

// An app's include rule selects its traffic to any destination and can't be
// cut around a tunnel's networks: the tunnel's status says so, per route it
// captures (not the pin, which goes via the physical gateway).
func TestAppRuleCapturesAreReported(t *testing.T) {
	in := testInput()
	in.Tunnels = []TunnelInput{{Name: "infra", Iface: "utun6", Routes: []string{"10.70.0.0/16"}, Bypass: []netip.Addr{netip.MustParseAddr("198.51.100.7")}}}
	tp := PlanTunnels(in)
	rules := []domain.ManagedRule{
		{PolicyRule: domain.PolicyRule{Priority: ModelBRulePrio, Selector: "to 172.16.0.0/12", Table: ModelBTable, Family: domain.FamilyV4}},
	}
	if got := AppRuleCaptures(tp, rules); len(got) != 0 {
		t.Fatalf("destination rules capture nothing: %+v", got)
	}
	rules = append(rules, domain.ManagedRule{PolicyRule: domain.PolicyRule{Priority: ModelBRulePrio, Selector: "user 501", Family: domain.FamilyV4, RouteToIface: "utun3", RouteToGW: "10.8.0.1"}})
	got := AppRuleCaptures(tp, rules)["infra"]
	if len(got) != 1 || got[0].Route != "10.70.0.0/16" || !strings.Contains(got[0].Reason, "user 501") || !strings.Contains(got[0].Reason, "utun3") {
		t.Fatalf("captures = %+v", got)
	}
}

// Cutting a prefix around networks keeps exactly what lies outside them.
func TestAroundTunnels(t *testing.T) {
	p := netip.MustParsePrefix
	for _, c := range []struct {
		in, nets []netip.Prefix
		want     string
	}{
		{[]netip.Prefix{p("10.0.0.0/8")}, nil, "10.0.0.0/8"},
		{[]netip.Prefix{p("10.0.0.0/8")}, []netip.Prefix{p("10.0.0.0/8")}, ""},
		{[]netip.Prefix{p("10.1.0.0/16")}, []netip.Prefix{p("10.0.0.0/8")}, ""},
		{[]netip.Prefix{p("10.0.0.0/8")}, []netip.Prefix{p("10.0.0.0/9")}, "10.128.0.0/9"},
		{[]netip.Prefix{p("10.0.0.0/8")}, []netip.Prefix{p("192.168.0.0/16"), p("fd00::/8")}, "10.0.0.0/8"},
		{[]netip.Prefix{p("10.0.0.0/30")}, []netip.Prefix{p("10.0.0.1/32"), p("10.0.0.2/32")}, "10.0.0.0/32,10.0.0.3/32"},
		{[]netip.Prefix{p("fd00::/8")}, []netip.Prefix{p("fd00::/9")}, "fd80::/9"},
	} {
		var got []string
		for _, q := range aroundTunnels(c.in, c.nets) {
			got = append(got, q.String())
		}
		if strings.Join(got, ",") != c.want {
			t.Errorf("%v around %v = %v, want %s", c.in, c.nets, got, c.want)
		}
	}
}
