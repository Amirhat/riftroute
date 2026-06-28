package routing

import (
	"net/netip"
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
	desired, err := BuildDesired(testInput(excludeProfile()))
	if err != nil {
		t.Fatal(err)
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
	if _, ok := byCIDR["10.0.0.0/8"]; !ok {
		t.Fatalf("missing cidr route: %+v", desired)
	}
}

func TestBuildDesiredSkipsDisabledAndInclude(t *testing.T) {
	disabled := excludeProfile()
	disabled.Enabled = false
	inc := excludeProfile()
	inc.ID, inc.Mode = "p2", domain.ModeInclude
	desired, err := BuildDesired(testInput(disabled, inc))
	if err != nil {
		t.Fatal(err)
	}
	if len(desired) != 0 {
		t.Fatalf("disabled + include should yield nothing, got %+v", desired)
	}
}

func TestBuildDesiredAutoGatewayMissing(t *testing.T) {
	in := testInput(excludeProfile())
	in.GatewayV4 = netip.Addr{} // no physical gateway resolvable
	if _, err := BuildDesired(in); err == nil {
		t.Fatal("expected error when gateway: auto cannot resolve")
	}
}

func TestReconcileAddsAndInverse(t *testing.T) {
	desired, _ := BuildDesired(testInput(excludeProfile()))
	plan := Reconcile(desired, nil, "linux")
	if len(plan.Ops) != 2 {
		t.Fatalf("want 2 add ops, got %d", len(plan.Ops))
	}
	for _, op := range plan.Ops {
		if op.Kind != domain.OpAddRoute {
			t.Fatalf("expected add ops, got %s", op.Kind)
		}
	}
	// inverse must be reverse-ordered deletes that exactly undo the adds.
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

func TestReconcileDelsWhenDesiredEmpty(t *testing.T) {
	actual, _ := BuildDesired(testInput(excludeProfile()))
	plan := Reconcile(nil, actual, "linux")
	if len(plan.Ops) != 2 {
		t.Fatalf("want 2 del ops, got %d", len(plan.Ops))
	}
	for _, op := range plan.Ops {
		if op.Kind != domain.OpDelRoute {
			t.Fatalf("expected del ops, got %s", op.Kind)
		}
	}
}

func TestReconcileNoChange(t *testing.T) {
	d, _ := BuildDesired(testInput(excludeProfile()))
	plan := Reconcile(d, d, "linux")
	if len(plan.Ops) != 0 {
		t.Fatalf("expected no ops when desired==actual, got %d", len(plan.Ops))
	}
}

func TestCommandPreviewPerOS(t *testing.T) {
	d, _ := BuildDesired(testInput(excludeProfile()))
	macPlan := Reconcile(d, nil, "darwin")
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
	linuxPlan := Reconcile(d, nil, "linux")
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
	// kernel says VPN (drift) until reconciled.
	kernel := domain.RouteDecision{Reachable: true, Iface: "utun3", ViaVPN: true}
	if !Drift(kernel, dec) {
		t.Fatal("expected drift between kernel(VPN) and simulated(direct)")
	}
}
