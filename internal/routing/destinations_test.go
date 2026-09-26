package routing

import (
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

func TestDestinationsHoldWhatTheProfilesStillRoute(t *testing.T) {
	d := ProfileDestinations(DesiredInput{
		Profiles: []domain.Profile{
			{ID: "ex", Enabled: true, Mode: domain.ModeExclude, Rules: []domain.Rule{
				{Type: domain.RuleCIDR, Value: "10.70.8.0/24"}, {Type: domain.RuleCIDR, Value: "10.70.9.0/24"},
				{Type: domain.RuleDomain, Value: "example.com"},
			}},
			{ID: "inc", Enabled: true, Mode: domain.ModeInclude, Lists: []string{"corp"}},
			{ID: "off", Enabled: false, Mode: domain.ModeExclude, Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "172.16.0.0/12"}}},
		},
		Domains: map[string][]string{"example.com": {"198.51.100.7"}},
		Lists:   map[string][]string{"corp": {"10.0.0.0/8", "fd00::/8"}},
	})
	route := func(dst string, fam domain.Family, table string) domain.Route {
		return domain.Route{DstCIDR: dst, Family: fam, Table: table}
	}
	rule := func(sel string, fam domain.Family) domain.PolicyRule {
		return domain.PolicyRule{Selector: sel, Family: fam}
	}
	for _, c := range []struct {
		name string
		got  bool
		want bool
	}{
		{"an aggregate of two of the profile's networks", d.HoldsRoute(route("10.70.8.0/23", domain.FamilyV4, "")), true},
		{"a piece of one", d.HoldsRoute(route("10.70.9.128/25", domain.FamilyV4, "")), true},
		{"a domain rule's address", d.HoldsRoute(route("198.51.100.7/32", domain.FamilyV4, "")), true},
		{"wider than what's routed", d.HoldsRoute(route("10.70.0.0/16", domain.FamilyV4, "")), false},
		{"a disabled profile's", d.HoldsRoute(route("172.16.0.0/12", domain.FamilyV4, "")), false},
		{"an include profile's network as a route", d.HoldsRoute(route("10.1.0.0/16", domain.FamilyV4, "")), false},
		{"a route in a table", d.HoldsRoute(route("0.0.0.0/0", domain.FamilyV4, "riftroute")), true},
		{"an include rule's piece", d.HoldsRule(rule("to 10.64.0.0/14", domain.FamilyV4)), true},
		{"a v6 include rule", d.HoldsRule(rule("to fd00:1::/32", domain.FamilyV6)), true},
		{"the wrong family", d.HoldsRule(rule("to 10.64.0.0/14", domain.FamilyV6)), false},
		{"a rule inside the include list", d.HoldsRule(rule("to 10.70.8.0/24", domain.FamilyV4)), true},
		{"a rule no profile routes", d.HoldsRule(rule("to 192.0.2.0/24", domain.FamilyV4)), false},
		{"an app rule", d.HoldsRule(rule("fwmark "+ModelBMark, domain.FamilyV4)), true},
	} {
		if c.got != c.want {
			t.Errorf("%s: holds = %v, want %v", c.name, c.got, c.want)
		}
	}
}

// A domain rule with no addresses makes its mode unsure: nothing outside
// what the mode is known to route is judged unrouted. The other mode is
// still judged.
func TestDestinationsDontJudgeAModeWithAnUnresolvedDomain(t *testing.T) {
	d := ProfileDestinations(DesiredInput{
		Profiles: []domain.Profile{
			{ID: "ex", Enabled: true, Mode: domain.ModeExclude, Rules: []domain.Rule{{Type: domain.RuleDomain, Value: "corp.example.com"}}},
			{ID: "inc", Enabled: true, Mode: domain.ModeInclude, Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.0.0.0/8"}}},
			{ID: "off", Enabled: false, Mode: domain.ModeInclude, Rules: []domain.Rule{{Type: domain.RuleDomain, Value: "gone.example.com"}}},
		},
		Domains: map[string][]string{},
	})
	if !d.HoldsRoute(domain.Route{DstCIDR: "10.70.1.5/32", Family: domain.FamilyV4}) {
		t.Error("an exclude route was judged unrouted while an exclude domain rule is unresolved")
	}
	if d.HoldsRule(domain.PolicyRule{Selector: "to 192.0.2.0/24", Family: domain.FamilyV4}) {
		t.Error("an include rule no include profile routes held: a disabled profile's unresolved domain made the mode unsure")
	}
}
