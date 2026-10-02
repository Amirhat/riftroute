package core

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/routing"
)

// A Tailscale beside us (Linux, its routes in table 52) shows in the state
// and the doctor; a tunnel route keeps its networks out; with its exit node
// on, the routes are mirrored past it — the tunnels' too.
func TestTailscaleBeside(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	if st, _ := svc.State(ctx); st.Tailscale != nil {
		t.Fatalf("Tailscale without one: %+v", st.Tailscale)
	}
	svc.Provider().(*fake.Provider).SetTailscale(true, false)
	st, err := svc.State(ctx)
	if err != nil || st.Tailscale == nil || st.Tailscale.Iface != "tailscale0" || st.Tailscale.ExitNode ||
		!strings.Contains(strings.Join(st.Tailscale.Networks, ","), "10.20.0.0/16") {
		t.Fatalf("state: %+v %v", st.Tailscale, err)
	}
	for _, v := range st.VPN.Interfaces {
		if v == "tailscale0" {
			t.Error("Tailscale counted as the VPN without its exit node")
		}
	}
	found := false
	for _, c := range svc.Doctor(ctx).Checks {
		found = found || c.Name == "tailscale" && strings.Contains(c.Detail, "tailscale0")
	}
	if !found {
		t.Error("the doctor doesn't mention Tailscale")
	}

	withTunnels(svc, routing.TunnelInput{Name: "lab", Iface: "utun6", Routes: []string{"10.0.0.0/8", "100.0.0.0/8"}})
	desired, _, _, err := svc.DesiredManaged(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range desired {
		p := netip.MustParsePrefix(d.DstCIDR)
		for _, n := range []string{"10.20.0.0/16", "100.64.0.0/10"} {
			if q := netip.MustParsePrefix(n); q.Bits() < p.Bits() && q.Contains(p.Addr()) {
				t.Errorf("%s (%s) takes Tailscale's %s", p, d.ProfileID, q)
			}
		}
		if p.Contains(netip.MustParseAddr("100.100.100.100")) {
			t.Errorf("%s carries MagicDNS", p)
		}
		if d.Table == routing.BypassTable {
			t.Errorf("a copy without the exit node: %+v", d)
		}
	}

	svc.Provider().(*fake.Provider).SetTailscale(true, true)
	routes, rules, _, _, _ := svc.TunnelsForApply(ctx, nil)
	copies := 0
	for _, r := range routes {
		if r.Table == routing.BypassTable {
			copies++
		}
	}
	bypass, first := false, false
	for _, r := range rules {
		bypass = bypass || r.Table == routing.BypassTable
		first = first || r.Table == "52" && r.Priority == routing.TailscaleRulePrio
	}
	if copies == 0 || !bypass || !first {
		t.Fatalf("exit node: %d copies, bypass rule %v, Tailscale's table first %v", copies, bypass, first)
	}
	if st, _ := svc.State(ctx); !st.Tailscale.ExitNode {
		t.Fatal("the exit node isn't seen")
	}
}
