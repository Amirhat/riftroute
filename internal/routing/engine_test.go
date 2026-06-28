package routing

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

func excludeProfile() domain.Profile {
	return domain.Profile{
		ID: "p1", Name: "work-direct", Enabled: true, Mode: domain.ModeExclude,
		Gateway: "auto", Priority: 100,
		Rules: []domain.Rule{
			{Type: domain.RuleCIDR, Value: "10.0.0.0/8"},
			{Type: domain.RuleIP, Value: "8.8.8.8"},
			{Type: domain.RuleDomain, Value: "example.com"}, // deferred → skipped
		},
	}
}

func testInput(profiles ...domain.Profile) DesiredInput {
	return DesiredInput{
		Profiles:    profiles,
		GatewayV4:   netip.MustParseAddr("192.168.1.1"),
		PhysIfaceV4: "en0",
		Platform:    "linux",
		Now:         time.Unix(0, 0),
	}
}

func TestBuildDesiredExcludeModelA(t *testing.T) {
	desired, rules, err := BuildDesired(testInput(excludeProfile()))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("exclude mode should emit no rules, got %d", len(rules))
	}
	if len(desired) != 2 {
		t.Fatalf("want 2 routes (cidr + ip; domain skipped), got %d: %+v", len(desired), desired)
	}
	byCIDR := map[string]domain.ManagedRoute{}
	for _, r := range desired {
		byCIDR[r.DstCIDR] = r
	}
	host := byCIDR["8.8.8.8/32"]
	if host.Gateway != "192.168.1.1" || host.Iface != "en0" || host.Owner != domain.OwnerRiftRoute || host.Proto != "riftroute" {
		t.Fatalf("host bypass wrong: %+v", host)
	}
}

func TestBuildDesiredExpandsLists(t *testing.T) {
	p := domain.Profile{
		ID: "p1", Name: "work", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.0.0.0/8"}},
		Lists: []string{"rfc1918"},
	}
	in := testInput(p)
	in.Lists = map[string][]string{"rfc1918": {"172.16.0.0/12", "192.168.0.0/16"}}
	routes, _, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range routes {
		got[r.DstCIDR] = true
	}
	for _, want := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		if !got[want] {
			t.Fatalf("expected route %s from rule+list expansion, got %+v", want, routes)
		}
	}
}

func TestBuildDesiredExpandsDomains(t *testing.T) {
	p := domain.Profile{
		ID: "p1", Name: "cdn", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleDomain, Value: "cdn.example.com"}},
	}
	in := testInput(p)
	in.Domains = map[string][]string{"cdn.example.com": {"1.2.3.4", "5.6.7.8"}}
	routes, _, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range routes {
		got[r.DstCIDR] = true
	}
	if !got["1.2.3.4/32"] || !got["5.6.7.8/32"] {
		t.Fatalf("domain rule should expand to its resolved /32s, got %+v", routes)
	}
}

func TestBuildDesiredSkipsDisabled(t *testing.T) {
	disabled := excludeProfile()
	disabled.Enabled = false
	desired, rules, err := BuildDesired(testInput(disabled))
	if err != nil {
		t.Fatal(err)
	}
	if len(desired) != 0 || len(rules) != 0 {
		t.Fatalf("disabled profile should yield nothing, got %d routes %d rules", len(desired), len(rules))
	}
}

func TestBuildDesiredIncludeModelB(t *testing.T) {
	in := testInput(domain.Profile{
		ID: "p2", Name: "only-tunnel", Enabled: true, Mode: domain.ModeInclude,
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "1.1.1.0/24"}},
	})
	in.PolicyRouting = true
	in.VPNGatewayV4 = netip.MustParseAddr("10.8.0.1")
	in.VPNIfaceV4 = "utun3"

	routes, rules, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	// One rule selecting the destination into the dedicated table.
	if len(rules) != 1 || rules[0].Table != ModelBTable || rules[0].Selector != "to 1.1.1.0/24" {
		t.Fatalf("include rule wrong: %+v", rules)
	}
	// One default route in the dedicated table via the tunnel.
	if len(routes) != 1 {
		t.Fatalf("want 1 table-default route, got %+v", routes)
	}
	def := routes[0].Route
	if def.DstCIDR != "0.0.0.0/0" || def.Table != ModelBTable || def.Iface != "utun3" || def.Gateway != "10.8.0.1" {
		t.Fatalf("table default wrong: %+v", def)
	}
}

func TestBuildDesiredAppRuleEmitsFwmark(t *testing.T) {
	in := testInput(domain.Profile{
		ID: "p2", Name: "apps-tunnel", Enabled: true, Mode: domain.ModeInclude,
		Rules: []domain.Rule{
			{Type: domain.RuleApp, Value: "firefox"},
			{Type: domain.RuleCIDR, Value: "1.1.1.0/24"},
		},
	})
	in.PolicyRouting = true
	in.VPNGatewayV4 = netip.MustParseAddr("10.8.0.1")
	in.VPNIfaceV4 = "utun3"
	_, rules, err := BuildDesired(in)
	if err != nil {
		t.Fatal(err)
	}
	var sawFwmark, sawCIDR bool
	for _, r := range rules {
		if strings.Contains(r.Selector, "fwmark") && r.Table == ModelBTable {
			sawFwmark = true
		}
		if r.Selector == "to 1.1.1.0/24" {
			sawCIDR = true
		}
	}
	if !sawFwmark {
		t.Fatalf("app rule should emit a fwmark rule, got %+v", rules)
	}
	if !sawCIDR {
		t.Fatalf("cidr rule should still emit a to-rule, got %+v", rules)
	}
}

func TestBuildDesiredIncludeNeedsPolicyRouting(t *testing.T) {
	in := testInput(domain.Profile{
		ID: "p2", Name: "only-tunnel", Enabled: true, Mode: domain.ModeInclude,
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "1.1.1.0/24"}},
	})
	in.PolicyRouting = false // e.g. macOS
	if _, _, err := BuildDesired(in); err == nil {
		t.Fatal("include mode without policy routing should error")
	}
}

func TestBuildDesiredAutoGatewayMissing(t *testing.T) {
	in := testInput(excludeProfile())
	in.GatewayV4 = netip.Addr{} // no physical gateway resolvable
	if _, _, err := BuildDesired(in); err == nil {
		t.Fatal("expected error when gateway: auto cannot resolve")
	}
}

func TestReconcileAddsAndInverse(t *testing.T) {
	desired, _, _ := BuildDesired(testInput(excludeProfile()))
	plan := Reconcile(desired, nil, nil, nil, "linux")
	if len(plan.Ops) != 2 {
		t.Fatalf("want 2 add ops, got %d", len(plan.Ops))
	}
	for _, op := range plan.Ops {
		if op.Kind != domain.OpAddRoute {
			t.Fatalf("expected add ops, got %s", op.Kind)
		}
	}
	if len(plan.Inverse) != 2 {
		t.Fatalf("want 2 inverse ops, got %d", len(plan.Inverse))
	}
	for _, op := range plan.Inverse {
		if op.Kind != domain.OpDelRoute {
			t.Fatalf("inverse of adds must be deletes, got %s", op.Kind)
		}
	}
	if plan.Inverse[0].Route.DstCIDR != plan.Ops[1].Route.DstCIDR {
		t.Fatal("inverse must be reverse-ordered")
	}
}

func TestReconcileRulesAddAndInverse(t *testing.T) {
	in := testInput(domain.Profile{
		ID: "p2", Name: "only-tunnel", Enabled: true, Mode: domain.ModeInclude,
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "1.1.1.0/24"}},
	})
	in.PolicyRouting = true
	in.VPNGatewayV4 = netip.MustParseAddr("10.8.0.1")
	in.VPNIfaceV4 = "utun3"
	routes, rules, _ := BuildDesired(in)

	plan := Reconcile(routes, nil, rules, nil, "linux")
	// Expect the table default route added before the rule (connectivity order).
	if len(plan.Ops) != 2 {
		t.Fatalf("want 2 ops (route + rule), got %d: %+v", len(plan.Ops), plan.Ops)
	}
	if plan.Ops[0].Kind != domain.OpAddRoute || plan.Ops[1].Kind != domain.OpAddRule {
		t.Fatalf("route add must precede rule add: %+v", plan.Ops)
	}
	// Inverse: del rule before del route.
	if plan.Inverse[0].Kind != domain.OpDelRule || plan.Inverse[1].Kind != domain.OpDelRoute {
		t.Fatalf("inverse must del rule before route: %+v", plan.Inverse)
	}
}

func TestReconcileNoChange(t *testing.T) {
	d, _, _ := BuildDesired(testInput(excludeProfile()))
	plan := Reconcile(d, d, nil, nil, "linux")
	if len(plan.Ops) != 0 {
		t.Fatalf("expected no ops when desired==actual, got %d", len(plan.Ops))
	}
}

func TestCommandPreviewPerOS(t *testing.T) {
	d, _, _ := BuildDesired(testInput(excludeProfile()))
	macPlan := Reconcile(d, nil, nil, nil, "darwin")
	var sawHost bool
	for _, op := range macPlan.Ops {
		if op.Route.DstCIDR == "8.8.8.8/32" {
			sawHost = true
			if op.Command[0] != "route" || op.Command[3] != "-host" {
				t.Fatalf("darwin host add command wrong: %v", op.Command)
			}
		}
	}
	if !sawHost {
		t.Fatal("missing host op")
	}
	linuxPlan := Reconcile(d, nil, nil, nil, "linux")
	if linuxPlan.Ops[0].Command[0] != "ip" {
		t.Fatalf("linux command should use ip: %v", linuxPlan.Ops[0].Command)
	}
}

func TestSimulateAndDrift(t *testing.T) {
	routes := []domain.Route{
		{DstCIDR: "0.0.0.0/0", Iface: "utun3", Owner: domain.OwnerVPN, Family: domain.FamilyV4},
		{DstCIDR: "8.8.8.0/24", Iface: "en0", Owner: domain.OwnerRiftRoute, Family: domain.FamilyV4, Profile: "p1"},
	}
	dec := Simulate(routes, netip.MustParseAddr("8.8.8.8"), nil)
	if dec.MatchedCIDR != "8.8.8.0/24" || dec.Iface != "en0" || dec.ViaVPN {
		t.Fatalf("simulate should pick the /24 bypass: %+v", dec)
	}
	kernel := domain.RouteDecision{Reachable: true, Iface: "utun3", ViaVPN: true}
	if !Drift(kernel, dec) {
		t.Fatal("expected drift between kernel(VPN) and simulated(direct)")
	}
}
