package reconcile_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/routing"
)

// Connecting a tunnel whose network an installed include rule covers: the
// rule is matched before the routing table and would capture the tunnel's
// traffic into the VPN. The tunnel apply cuts the rule around the tunnel's
// network — with auto-apply off too — and leaves the app rule alone.
func TestTunnelConnectCutsIncludeRulesAroundItsNetwork(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	for _, sel := range []string{"to 10.0.0.0/8", "from all fwmark " + routing.ModelBMark} {
		if err := h.prov.AddRule(ctx, domain.ManagedRule{PolicyRule: domain.PolicyRule{
			Priority: routing.ModelBRulePrio, Selector: sel, Table: routing.ModelBTable, Family: domain.FamilyV4, Proto: "riftroute",
		}}); err != nil {
			t.Fatal(err)
		}
	}
	h.setTunnels(routing.TunnelInput{Name: "infra", Iface: "utun9", Routes: []string{"10.70.0.0/16"}})
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}

	rules, err := h.prov.ListRules(ctx, domain.FamilyV4)
	if err != nil {
		t.Fatal(err)
	}
	tunnelNet := netip.MustParsePrefix("10.70.0.0/16")
	var dests, apps int
	for _, r := range rules {
		if r.Proto != "riftroute" {
			continue
		}
		dst, ok := strings.CutPrefix(r.Selector, "to ")
		if !ok {
			apps++
			continue
		}
		dests++
		if netip.MustParsePrefix(dst).Overlaps(tunnelNet) {
			t.Errorf("include rule %q still captures the tunnel's network", r.Selector)
		}
	}
	if dests != 8 || apps != 1 {
		t.Errorf("%d destination rule(s), %d app rule(s): %+v", dests, apps, rules)
	}
	if got := h.kernel(t)["10.70.0.0/16"]; len(got) != 1 || got[0] != "utun9" {
		t.Errorf("tunnel route = %v", got)
	}
}

// With auto-apply off, what a tunnel took comes back when it goes: the
// include rule it cut and the exclude route inside its network return on the
// disconnect's tunnel apply — no full apply is coming to do it, and without
// them that traffic would leave outside the VPN.
func TestTunnelDisconnectRestoresWhatItsConnectCut(t *testing.T) {
	h := newTunnelHarness(t) // auto-apply off
	ctx := context.Background()
	if err := h.prov.AddRule(ctx, domain.ManagedRule{PolicyRule: domain.PolicyRule{
		Priority: routing.ModelBRulePrio, Selector: "to 10.0.0.0/8", Table: routing.ModelBTable, Family: domain.FamilyV4, Proto: "riftroute",
	}}); err != nil {
		t.Fatal(err)
	}
	exclude := domain.ManagedRoute{Route: domain.Route{DstCIDR: "10.70.5.5/32", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4, Owner: domain.OwnerRiftRoute}, ProfileID: "p1"}
	h.own(t, exclude)

	h.setTunnels(routing.TunnelInput{Name: "infra", Iface: "utun9", Routes: []string{"10.70.0.0/16"}})
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.kernel(t)["10.70.5.5/32"]; len(got) != 0 {
		t.Fatalf("the exclude route didn't yield to the tunnel: %v", got)
	}

	h.setTunnels() // disconnected
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	rules, _ := h.prov.ListRules(ctx, domain.FamilyV4)
	var sels []string
	for _, r := range rules {
		if r.Proto == "riftroute" {
			sels = append(sels, r.Selector)
		}
	}
	if len(sels) != 1 || sels[0] != "to 10.0.0.0/8" {
		t.Errorf("include rules after the disconnect = %q, want the original back", sels)
	}
	if got := h.kernel(t)["10.70.5.5/32"]; len(got) != 1 || got[0] != "en0" {
		t.Errorf("exclude route after the disconnect = %v, want it back via en0", got)
	}
}
