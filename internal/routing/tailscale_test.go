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

// What a Tailscale beside us routes stays its own: include rules are cut
// around its networks, exclude destinations inside them yield, and (Linux)
// marked apps' traffic to them is sent to its table first.
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
		sel := strings.TrimPrefix(r.Selector, "to ")
		if r.Table == "52" {
			if r.Priority != TailscaleRulePrio {
				t.Errorf("Tailscale's rule at %d", r.Priority)
			}
			toTS = append(toTS, sel)
			continue
		}
		if p, err := netip.ParsePrefix(sel); err == nil {
			for _, n := range tailnet() {
				if p.Overlaps(n) {
					t.Errorf("include rule %s takes Tailscale's %s", p, n)
				}
			}
		}
	}
	if strings.Join(toTS, ",") != "10.20.0.0/16,100.64.0.0/10" {
		t.Errorf("rules to Tailscale's table: %v", toTS)
	}

	// macOS has no tables: no such rule; nor without Tailscale.
	in.Platform = "darwin"
	_, rules, _ = BuildDesired(in)
	for _, r := range rules {
		if r.Table == "52" {
			t.Errorf("a table-52 rule on macOS: %+v", r)
		}
	}
}

// With Tailscale's exit node on (Linux), its rule sends everything to its
// table before main: RiftRoute's main-table routes are copied into a table
// looked up first — cut around what Tailscale routes — and the copies go
// when the exit node does.
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
			p := netip.MustParsePrefix(r.DstCIDR)
			if p.Overlaps(netip.MustParsePrefix("10.20.0.0/16")) {
				t.Errorf("a copy takes Tailscale's subnet: %s", p)
			}
			if r.Gateway != "192.168.1.1" {
				t.Errorf("a copy with another next hop: %+v", r)
			}
		}
	}
	if !main["10.0.0.0/8"] || !main["8.8.8.8/32"] || copies < 2 {
		t.Fatalf("main %v, %d copies", main, copies)
	}
	var bypass []domain.ManagedRule
	for _, r := range rules {
		if r.Table == BypassTable {
			bypass = append(bypass, r)
		}
	}
	if len(bypass) != 1 || bypass[0].Priority != BypassRulePrio || bypass[0].Selector != "from all" || bypass[0].Family != domain.FamilyV4 {
		t.Fatalf("bypass rules %+v", bypass)
	}

	// No exit node, or macOS: no copies — and a set that held some loses them.
	in.TailscaleExitNode = false
	r2, rules2 := MirrorPastTailscale(routes, rules, in)
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
	if r3, _ := MirrorPastTailscale(r2, rules2, in); len(r3) != len(r2) {
		t.Fatal("copies on macOS")
	}
}
