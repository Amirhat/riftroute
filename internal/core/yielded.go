package core

import (
	"context"
	"encoding/json"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/routing"
)

// yielded is what the profiles' routes and include rules gave up to live
// tunnels (a destination inside a tunnel's networks goes into the tunnel):
// the routes dropped, and each rule cut with the pieces it was cut into. A
// tunnel apply puts them back before placing everything beside the tunnels
// live then, so they return when the tunnel goes — including with auto-apply
// off, where no full apply follows. Only what an apply already installed is
// ever put back — a full apply rewrites the record from the profiles — and
// only while a profile still routes it (stillWanted).
type yielded struct {
	Routes []domain.ManagedRoute `json:"routes,omitempty"`
	Rules  []yieldedRule         `json:"rules,omitempty"`
}

type yieldedRule struct {
	Rule   domain.ManagedRule   `json:"rule"`
	Pieces []domain.ManagedRule `json:"pieces,omitempty"`
}

const yieldedKey = "tunnels.yielded"

func (s *Service) loadYielded() yielded {
	var y yielded
	if s.store == nil {
		return y
	}
	if v, ok, err := s.store.GetSetting(yieldedKey); err == nil && ok {
		_ = json.Unmarshal([]byte(v), &y)
	}
	return y
}

// ForgetYielded drops the record: a panic is about to flush what it
// describes, and nothing may put it back. It runs right before the flush
// (safety.PanicSteps.Flushing), once the changes the panic settles have
// recorded theirs.
func (s *Service) ForgetYielded() { s.saveYielded(yielded{}) }

func (s *Service) saveYielded(y yielded) {
	if s.store == nil {
		return
	}
	b, err := json.Marshal(y)
	if err != nil {
		return
	}
	_ = s.store.SetSetting(yieldedKey, string(b))
}

// stillWanted is y less what no enabled profile routes any more. A record
// can outlive its profile: a deletion that changed nothing (its only route
// had yielded) records in the place of a change still on probation, and
// its record is lost with that change if it rolls back. This only ever
// takes put-backs away, so it never applies a change staged for the user.
// Coverage, not equality: what yielded may be a piece of a profile's rule,
// cut around a tunnel before it yielded to another.
//
// What can't be known isn't judged: when the profiles can't be read, an
// item isn't taken away; nor is one of a profile whose domain rule has no
// address of its family (DNS not up yet after a restart, a partial answer)
// — that profile's own items only, so an unrelated profile's typo never
// brings back a deleted one's route.
func (s *Service) stillWanted(ctx context.Context, y yielded) yielded {
	if (len(y.Routes) == 0 && len(y.Rules) == 0) || s.store == nil {
		return y
	}
	profiles, err := s.store.ListProfiles()
	if err != nil {
		return y
	}
	if _, err := s.store.ListLists(); err != nil {
		return y
	}
	domains, unresolved := s.lookupDomains(ctx, profiles)
	for v := range unresolved {
		domains[v] = nil // what the learner saw under it doesn't make it known
	}
	d := routing.ProfileDestinations(routing.DesiredInput{
		Profiles: profiles, Lists: s.listsMap(), Domains: domains,
	})
	var out yielded
	for _, r := range y.Routes {
		if d.HoldsRoute(r) {
			out.Routes = append(out.Routes, r)
		}
	}
	for _, r := range y.Rules {
		if d.HoldsRule(r.Rule) {
			out.Rules = append(out.Rules, r)
		}
	}
	return out
}

// putBackRoutes adds the yielded routes to routes (once each).
func (y yielded) putBackRoutes(routes []domain.ManagedRoute) []domain.ManagedRoute {
	have := map[string]bool{}
	for _, r := range routes {
		have[routing.RouteKey(r.Route)] = true
	}
	for _, r := range y.Routes {
		if k := routing.RouteKey(r.Route); !have[k] {
			have[k] = true
			routes = append(routes, r)
		}
	}
	return routes
}

// putBackRules replaces each yielded rule's pieces in rules with the rule.
func (y yielded) putBackRules(rules []domain.ManagedRule) []domain.ManagedRule {
	if len(y.Rules) == 0 {
		return rules
	}
	piece := map[string]bool{}
	for _, yr := range y.Rules {
		for _, p := range yr.Pieces {
			piece[routing.RuleKey(p.PolicyRule)] = true
		}
	}
	var out []domain.ManagedRule
	have := map[string]bool{}
	for _, r := range rules {
		k := routing.RuleKey(r.PolicyRule)
		if !piece[k] && !have[k] {
			have[k] = true
			out = append(out, r)
		}
	}
	for _, yr := range y.Rules {
		if k := routing.RuleKey(yr.Rule.PolicyRule); !have[k] {
			have[k] = true
			out = append(out, yr.Rule)
		}
	}
	return out
}

// yieldedTo is what of routes and rules gives way to the plan's live
// tunnels: routes not in placed, and rules the plan cuts, with their pieces.
func yieldedTo(tp routing.TunnelPlan, routes []domain.ManagedRoute, rules []domain.ManagedRule, placed []domain.ManagedRoute) yielded {
	var y yielded
	kept := map[string]bool{}
	for _, r := range placed {
		kept[routing.RouteKey(r.Route)] = true
	}
	for _, r := range routes {
		if !kept[routing.RouteKey(r.Route)] && r.ProfileID != "" {
			y.Routes = append(y.Routes, r)
		}
	}
	for _, r := range rules {
		parts := tp.RulesBeside([]domain.ManagedRule{r})
		if len(parts) == 1 && routing.RuleKey(parts[0].PolicyRule) == routing.RuleKey(r.PolicyRule) {
			continue
		}
		y.Rules = append(y.Rules, yieldedRule{Rule: r, Pieces: parts})
	}
	return y
}
