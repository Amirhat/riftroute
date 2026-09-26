package routing

import (
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

func route(profile, dst string, fam domain.Family, table string) domain.ManagedRoute {
	return domain.ManagedRoute{Route: domain.Route{DstCIDR: dst, Family: fam, Table: table}, ProfileID: profile}
}

func rule(profile, sel string, fam domain.Family) domain.ManagedRule {
	return domain.ManagedRule{PolicyRule: domain.PolicyRule{Selector: sel, Family: fam}, ProfileID: profile}
}

type holdsCase struct {
	name string
	got  bool
	want bool
}

func checkHolds(t *testing.T, cases []holdsCase) {
	t.Helper()
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: holds = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestDestinationsHoldWhatTheProfilesStillRoute(t *testing.T) {
	d := ProfileDestinations(DesiredInput{
		Profiles: []domain.Profile{
			{ID: "ex", Enabled: true, Mode: domain.ModeExclude, Rules: []domain.Rule{
				{Type: domain.RuleCIDR, Value: "10.70.8.0/24"}, {Type: domain.RuleCIDR, Value: "10.70.9.0/24"},
			}},
			{ID: "inc", Enabled: true, Mode: domain.ModeInclude, Lists: []string{"corp"}},
			{ID: "off", Enabled: false, Mode: domain.ModeExclude, Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "172.16.0.0/12"}}},
		},
		Lists: map[string][]string{"corp": {"10.0.0.0/8", "fd00::/8"}},
	})
	v4, v6 := domain.FamilyV4, domain.FamilyV6
	checkHolds(t, []holdsCase{
		{"an aggregate of two of the profile's networks", d.HoldsRoute(route("ex", "10.70.8.0/23", v4, "")), true},
		{"a piece of one", d.HoldsRoute(route("ex", "10.70.9.128/25", v4, "")), true},
		{"wider than what's routed", d.HoldsRoute(route("ex", "10.70.0.0/16", v4, "")), false},
		{"a disabled profile's", d.HoldsRoute(route("off", "172.16.0.0/12", v4, "")), false},
		{"an include profile's network as a route", d.HoldsRoute(route("inc", "10.1.0.0/16", v4, "")), false},
		{"a route in a table", d.HoldsRoute(route("", "0.0.0.0/0", v4, "riftroute")), true},
		{"an include rule's piece", d.HoldsRule(rule("inc", "to 10.64.0.0/14", v4)), true},
		{"a v6 include rule", d.HoldsRule(rule("inc", "to fd00:1::/32", v6)), true},
		{"the wrong family", d.HoldsRule(rule("inc", "to 10.64.0.0/14", v6)), false},
		{"a rule inside the include list", d.HoldsRule(rule("", "to 10.70.8.0/24", v4)), true},
		{"a rule no profile routes", d.HoldsRule(rule("", "to 192.0.2.0/24", v4)), false},
		{"an app rule", d.HoldsRule(rule("", "fwmark "+ModelBMark, v4)), true},
	})
}

// A domain rule with no address of a family makes its own profile unsure of
// that family — only its own items of that family hold for it. An unrelated
// profile's typo never holds a deleted or disabled profile's item.
func TestDestinationsDontJudgeWhatAProfileCantKnow(t *testing.T) {
	d := ProfileDestinations(DesiredInput{
		Profiles: []domain.Profile{
			{ID: "typo", Enabled: true, Mode: domain.ModeExclude, Rules: []domain.Rule{
				{Type: domain.RuleCIDR, Value: "192.0.2.0/24"}, {Type: domain.RuleDomain, Value: "typo.exampel.com"},
			}},
			{ID: "v4only", Enabled: true, Mode: domain.ModeExclude, Rules: []domain.Rule{{Type: domain.RuleDomain, Value: "corp.example.com"}}},
			{ID: "incdns", Enabled: true, Mode: domain.ModeInclude, Rules: []domain.Rule{{Type: domain.RuleDomain, Value: "vpn.example.com"}}},
			{ID: "off", Enabled: false, Mode: domain.ModeExclude, Rules: []domain.Rule{{Type: domain.RuleDomain, Value: "gone.example.com"}}},
		},
		Domains: map[string][]string{"corp.example.com": {"10.70.1.5"}},
	})
	v4, v6 := domain.FamilyV4, domain.FamilyV6
	checkHolds(t, []holdsCase{
		{"its own item outside what's known", d.HoldsRoute(route("typo", "10.70.9.0/24", v4, "")), true},
		{"a deleted profile's, beside another's typo", d.HoldsRoute(route("gone-for-good", "10.70.9.0/24", v4, "")), false},
		{"a disabled profile's unresolved domain", d.HoldsRoute(route("off", "10.70.9.0/24", v4, "")), false},
		{"a partial answer's missing family", d.HoldsRoute(route("v4only", "fd70::5/128", v6, "")), true},
		{"a partial answer's known family", d.HoldsRoute(route("v4only", "10.70.2.0/24", v4, "")), false},
		{"an exclude profile's unsure family, as a rule", d.HoldsRule(rule("typo", "to 10.70.9.0/24", v4)), false},
		{"an include profile's own rule", d.HoldsRule(rule("incdns", "to 10.9.9.9/32", v4)), true},
		{"an unattributed rule, beside an unsure include profile", d.HoldsRule(rule("", "to 10.9.9.9/32", v4)), false},
		{"a deleted include profile's rule", d.HoldsRule(rule("gone", "to 10.9.9.9/32", v4)), false},
	})
}

// A rule read from the kernel is the enabled include profile's that routes
// its whole network most tightly; none's if no enabled include profile does.
func TestIncludeOwnerIsTheProfileThatRoutesTheRule(t *testing.T) {
	d := ProfileDestinations(DesiredInput{Profiles: []domain.Profile{
		{ID: "ex", Enabled: true, Mode: domain.ModeExclude, Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.0.0.0/8"}}},
		{ID: "wide", Enabled: true, Mode: domain.ModeInclude, Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.0.0.0/8"}}},
		{ID: "a", Enabled: true, Mode: domain.ModeInclude, Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.70.8.0/24"}, {Type: domain.RuleCIDR, Value: "10.70.9.0/24"}}},
		{ID: "dns", Enabled: true, Mode: domain.ModeInclude, Rules: []domain.Rule{{Type: domain.RuleDomain, Value: "corp.example.com"}}},
		{ID: "wide2", Enabled: true, Mode: domain.ModeInclude, Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.0.0.0/8"}}},
		{ID: "off", Enabled: false, Mode: domain.ModeInclude, Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "172.16.0.0/12"}}},
	}, Domains: map[string][]string{"corp.example.com": {"10.1.2.3"}}})
	for _, c := range []struct{ sel, want string }{
		{"to 10.70.8.0/23", "a"}, // its two networks, aggregated, inside wide's /8
		{"to 10.70.9.128/25", "a"},
		{"to 10.1.2.3/32", "dns"},   // a domain's address inside wide's /8
		{"to 10.64.0.0/14", "wide"}, // a tie with wide2: the first
		{"to 10.0.0.0/8", "wide"},
		{"to 172.16.0.0/12", ""}, // a disabled profile's
		{"to 192.0.2.0/24", ""},
		{"fwmark " + ModelBMark, ""},
	} {
		if got := d.IncludeOwner(domain.PolicyRule{Selector: c.sel, Family: domain.FamilyV4}); got != c.want {
			t.Errorf("%s: owner = %q, want %q", c.sel, got, c.want)
		}
	}
}
