// Package routing is the engine: it builds desired state from enabled profiles,
// reconciles it against actual managed routes+rules into an ordered plan WITH a
// precomputed inverse (the spine of the Apply Protocol, spec §2.2), and provides
// a longest-prefix-match simulator for route-explain and conflict detection
// (spec §5.2/§7.2). Pure logic — no kernel, no I/O — so it is exhaustively
// testable against the fake provider.
package routing

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// Model B (Linux policy routing) allocation: a dedicated table for include-mode
// traffic, and a fixed priority band for the selecting rules (spec §4.3/§5.4).
const (
	ModelBTable      = "5252"
	ModelBRulePrio   = 5252
	ModelBMark       = "0x5252" // fwmark for per-app traffic steered into the table
	modelBProfileTag = "model-b"
)

// DesiredInput is everything the builder needs to derive desired managed state.
type DesiredInput struct {
	Profiles    []domain.Profile
	GatewayV4   netip.Addr // resolved physical gateway (VPN-independent)
	GatewayV6   netip.Addr
	PhysIfaceV4 string
	PhysIfaceV6 string
	// VPN tunnel next-hop/iface, for include mode (Model B) destinations that go
	// INTO the tunnel. Zero when no tunnel is active.
	VPNGatewayV4 netip.Addr
	VPNGatewayV6 netip.Addr
	VPNIfaceV4   string
	VPNIfaceV6   string

	// Lists maps a list name to its effective CIDR/IP entries (static + the
	// last-fetched remote cache); profiles reference lists by name (spec §5.1).
	Lists map[string][]string
	// Domains maps a domain rule's value to its resolved A/AAAA addresses (spec
	// §5.1 domain rules); the daemon re-resolves these in the background.
	Domains map[string][]string

	Platform      string // "darwin" | "linux" | "fake"
	PolicyRouting bool   // whether Model B (include mode) is available
	Now           time.Time
}

// BuildDesired computes the managed routes + rules implied by the enabled
// profiles. exclude mode (Model A): bypass routes via the physical gateway.
// include mode (Model B, Linux only): a dedicated table with a default via the
// tunnel + rules selecting the profile's destinations into it. Prefixes are
// aggregated per profile/family to keep the kernel table small (spec §5.2).
func BuildDesired(in DesiredInput) ([]domain.ManagedRoute, []domain.ManagedRule, error) {
	profs := append([]domain.Profile{}, in.Profiles...)
	sort.SliceStable(profs, func(i, j int) bool { return profs[i].Priority > profs[j].Priority })

	seenRoute := map[string]bool{}
	seenRule := map[string]bool{}
	var routes []domain.ManagedRoute
	var rules []domain.ManagedRule
	includeFamilies := map[domain.Family]bool{}

	for _, p := range profs {
		if !p.Enabled {
			continue
		}
		byFamily := map[domain.Family][]netip.Prefix{}
		for _, r := range p.Rules {
			if pfx, fam, ok := ruleToPrefix(r); ok {
				byFamily[fam] = append(byFamily[fam], pfx)
				continue
			}
			// domain rules expand to their resolved A/AAAA addresses (asn/country
			// need a GeoIP DB — deferred).
			if r.Type == domain.RuleDomain {
				for _, ip := range in.Domains[r.Value] {
					if pfx, fam, ok := entryToPrefix(ip); ok {
						byFamily[fam] = append(byFamily[fam], pfx)
					}
				}
			}
		}
		// Expand referenced lists (static + fetched remote entries).
		for _, listName := range p.Lists {
			for _, e := range in.Lists[listName] {
				if pfx, fam, ok := entryToPrefix(e); ok {
					byFamily[fam] = append(byFamily[fam], pfx)
				}
			}
		}

		switch p.Mode {
		case domain.ModeInclude:
			if !in.PolicyRouting {
				return nil, nil, fmt.Errorf("profile %q: include mode requires policy routing (Linux Model B / macOS PF route-to); unavailable on this platform", p.Name)
			}
			if in.Platform == "darwin" {
				// macOS: PF route-to anchors — the Darwin analogue of Model B. No
				// dedicated table/default; the tunnel target rides on each rule.
				if err := buildDarwinInclude(p, byFamily, in, seenRule, &rules); err != nil {
					return nil, nil, err
				}
				break
			}
			addRule := func(pr domain.PolicyRule, fam domain.Family) {
				k := RuleKey(pr)
				if seenRule[k] {
					return
				}
				seenRule[k] = true
				rules = append(rules, domain.ManagedRule{PolicyRule: pr, ProfileID: p.ID, CreatedAt: in.Now})
				includeFamilies[fam] = true
			}
			for fam, prefixes := range byFamily {
				for _, pfx := range Aggregate(prefixes) {
					addRule(domain.PolicyRule{Priority: ModelBRulePrio, Selector: "to " + pfx.String(), Table: ModelBTable, Family: fam, Proto: protoFor(in.Platform)}, fam)
				}
			}
			// Per-app routing: an `app` rule steers the app's fwmark-tagged traffic
			// into the tunnel table (spec §6). The cgroup→mark classification is set
			// up separately by the nft marker (internal/perapp).
			for _, r := range p.Rules {
				if r.Type == domain.RuleApp {
					addRule(domain.PolicyRule{Priority: ModelBRulePrio, Selector: "fwmark " + ModelBMark, Table: ModelBTable, Family: domain.FamilyV4, Proto: protoFor(in.Platform)}, domain.FamilyV4)
					break
				}
			}
		default: // exclude / Model A
			skipped, families := 0, 0
			var skipErr error
			for fam, prefixes := range byFamily {
				families++
				gw, iface, err := resolveGateway(p.Gateway, fam, in)
				if err != nil {
					// No usable physical path for this family: auto-resolution
					// found no gateway (v6 prefixes on a v4-only network — every
					// AAAA answer of a domain rule lands here), or the explicit
					// gateway belongs to the other family. Skipping is fail-safe
					// for exclude mode: those destinations simply stay on the
					// tunnel instead of the whole profile becoming unappliable.
					// A malformed gateway — or NO buildable family at all (checked
					// below) — remains a hard error, so drift still shows
					// attention-needed instead of a false "in sync".
					if _, perr := netip.ParseAddr(p.Gateway); perr == nil || p.Gateway == "" || p.Gateway == "auto" {
						skipped++
						skipErr = err
						continue
					}
					return nil, nil, fmt.Errorf("profile %q: %w", p.Name, err)
				}
				for _, pfx := range Aggregate(prefixes) {
					rt := domain.Route{
						DstCIDR: pfx.String(), Gateway: gw.String(), Iface: iface, Family: fam,
						Owner: domain.OwnerRiftRoute, Proto: protoFor(in.Platform), Profile: p.ID,
					}
					if !addRoute(seenRoute, &routes, rt, p.ID, in.Now) {
						continue
					}
				}
			}
			if families > 0 && skipped == families {
				return nil, nil, fmt.Errorf("profile %q: %w", p.Name, skipErr)
			}
		}
	}

	// For each family with include rules, the dedicated table needs a default via
	// the tunnel (spec §5.4 Model B). Refuse if no tunnel is active (fail-safe).
	for fam := range includeFamilies {
		vpnGW, vpnIface := vpnFor(fam, in)
		if vpnIface == "" {
			return nil, nil, fmt.Errorf("include mode: no active VPN tunnel for %s to route into", fam)
		}
		def := "0.0.0.0/0"
		if fam == domain.FamilyV6 {
			def = "::/0"
		}
		gwStr := "" // a point-to-point tunnel default is on-link (no gateway)
		if vpnGW.IsValid() {
			gwStr = vpnGW.String()
		}
		rt := domain.Route{
			DstCIDR: def, Gateway: gwStr, Iface: vpnIface, Family: fam,
			Owner: domain.OwnerRiftRoute, Proto: protoFor(in.Platform), Table: ModelBTable, Profile: modelBProfileTag,
		}
		addRoute(seenRoute, &routes, rt, modelBProfileTag, in.Now)
	}

	sort.SliceStable(routes, func(i, j int) bool { return RouteKey(routes[i].Route) < RouteKey(routes[j].Route) })
	sort.SliceStable(rules, func(i, j int) bool { return RuleKey(rules[i].PolicyRule) < RuleKey(rules[j].PolicyRule) })
	return routes, rules, nil
}

// buildDarwinInclude emits macOS PF route-to rules for an include-mode profile:
// each aggregated destination prefix — and each per-app uid — is steered into the
// active tunnel. Unlike Linux Model B there is no dedicated table or table
// default; the route-to target (tunnel iface + optional gateway) is carried on
// the rule itself, and the macOS provider renders it into a `pass out quick
// route-to (...)` anchor rule. Refuses when no tunnel is active (fail-safe: never
// emit an include rule that would blackhole matched traffic into a dead iface).
func buildDarwinInclude(p domain.Profile, byFamily map[domain.Family][]netip.Prefix, in DesiredInput, seenRule map[string]bool, rules *[]domain.ManagedRule) error {
	add := func(pr domain.PolicyRule) {
		k := RuleKey(pr)
		if seenRule[k] {
			return
		}
		seenRule[k] = true
		*rules = append(*rules, domain.ManagedRule{PolicyRule: pr, ProfileID: p.ID, CreatedAt: in.Now})
	}
	mkRule := func(selector string, fam domain.Family) (domain.PolicyRule, bool) {
		vpnGW, vpnIface := vpnFor(fam, in)
		if vpnIface == "" {
			return domain.PolicyRule{}, false
		}
		gwStr := ""
		if vpnGW.IsValid() {
			gwStr = vpnGW.String()
		}
		return domain.PolicyRule{
			Priority: ModelBRulePrio, Selector: selector, Family: fam,
			Proto: "riftroute", RouteToIface: vpnIface, RouteToGW: gwStr,
		}, true
	}

	for fam, prefixes := range byFamily {
		for _, pfx := range Aggregate(prefixes) {
			pr, ok := mkRule("to "+pfx.String(), fam)
			if !ok {
				return fmt.Errorf("profile %q: include mode has no active VPN tunnel for %s to route into", p.Name, fam)
			}
			add(pr)
		}
	}

	// Per-app (Darwin): macOS has no cgroup/fwmark, but PF matches on the socket
	// owner, so an `app` rule whose value is a uid/username steers that user's
	// egress into the tunnel. Applies to whichever families have a live tunnel.
	// The value is interpolated into a pfctl rule, so refuse anything that isn't
	// uid-like — one malformed token would fail the whole anchor load and take
	// every other rule down with it.
	for _, r := range p.Rules {
		if r.Type != domain.RuleApp {
			continue
		}
		if !domain.IsUIDLike(r.Value) {
			return fmt.Errorf("profile %q: on macOS, per-app rules match by uid/username (PF socket owner); %q is not a uid/username", p.Name, r.Value)
		}
		emitted := false
		for _, fam := range []domain.Family{domain.FamilyV4, domain.FamilyV6} {
			if pr, ok := mkRule("user "+r.Value, fam); ok {
				add(pr)
				emitted = true
			}
		}
		if !emitted {
			return fmt.Errorf("profile %q: per-app include rule %q has no active VPN tunnel to route into", p.Name, r.Value)
		}
	}
	return nil
}

func addRoute(seen map[string]bool, out *[]domain.ManagedRoute, rt domain.Route, profile string, now time.Time) bool {
	k := RouteKey(rt)
	if seen[k] {
		return false
	}
	seen[k] = true
	*out = append(*out, domain.ManagedRoute{Route: rt, ProfileID: profile, CreatedAt: now})
	return true
}

// Reconcile diffs desired against actual managed routes+rules and returns an
// ordered plan plus its exact inverse. Adds run before deletes, and within that
// table-routes precede the rules that reference them (and the reverse on
// teardown), so a rule never points at a missing table (connectivity-preserving).
func Reconcile(desiredRoutes, actualRoutes []domain.ManagedRoute, desiredRules, actualRules []domain.ManagedRule, platform string) domain.Plan {
	dr := indexRoutes(desiredRoutes)
	ar := indexRoutes(actualRoutes)
	drl := indexRules(desiredRules)
	arl := indexRules(actualRules)

	var routeAdds, routeDels, ruleAdds, ruleDels []domain.PlanOp
	for _, d := range desiredRoutes {
		if _, ok := ar[RouteKey(d.Route)]; !ok {
			routeAdds = append(routeAdds, makeRouteOp(domain.OpAddRoute, d, platform))
		}
	}
	for _, a := range actualRoutes {
		if _, ok := dr[RouteKey(a.Route)]; !ok {
			routeDels = append(routeDels, makeRouteOp(domain.OpDelRoute, a, platform))
		}
	}
	for _, d := range desiredRules {
		if _, ok := arl[RuleKey(d.PolicyRule)]; !ok {
			ruleAdds = append(ruleAdds, makeRuleOp(domain.OpAddRule, d, platform))
		}
	}
	for _, a := range actualRules {
		if _, ok := drl[RuleKey(a.PolicyRule)]; !ok {
			ruleDels = append(ruleDels, makeRuleOp(domain.OpDelRule, a, platform))
		}
	}

	// Order: add routes (incl. table defaults) → add rules → del rules → del
	// routes. So a rule is never live without its table, and the table default
	// outlives the rules during teardown.
	ops := append(append(append(append([]domain.PlanOp{}, routeAdds...), ruleAdds...), ruleDels...), routeDels...)
	return domain.Plan{Ops: ops, Inverse: invert(ops, platform)}
}

func invert(ops []domain.PlanOp, platform string) []domain.PlanOp {
	inv := make([]domain.PlanOp, 0, len(ops))
	for i := len(ops) - 1; i >= 0; i-- {
		op := ops[i]
		switch op.Kind {
		case domain.OpAddRoute:
			inv = append(inv, makeRouteOp(domain.OpDelRoute, *op.Route, platform))
		case domain.OpDelRoute:
			inv = append(inv, makeRouteOp(domain.OpAddRoute, *op.Route, platform))
		case domain.OpAddRule:
			inv = append(inv, makeRuleOp(domain.OpDelRule, *op.Rule, platform))
		case domain.OpDelRule:
			inv = append(inv, makeRuleOp(domain.OpAddRule, *op.Rule, platform))
		}
	}
	return inv
}

func makeRouteOp(kind domain.OpKind, mr domain.ManagedRoute, platform string) domain.PlanOp {
	cp := mr
	return domain.PlanOp{Kind: kind, Route: &cp, Command: commandForRoute(kind, mr.Route, platform), Human: humanForRoute(kind, mr.Route)}
}

func makeRuleOp(kind domain.OpKind, mr domain.ManagedRule, platform string) domain.PlanOp {
	cp := mr
	return domain.PlanOp{Kind: kind, Rule: &cp, Command: commandForRule(kind, mr.PolicyRule), Human: humanForRule(kind, mr.PolicyRule)}
}

// commandForRoute returns the exact arg-array a real provider would exec.
func commandForRoute(kind domain.OpKind, r domain.Route, platform string) []string {
	if platform == "darwin" {
		scope := "-net"
		if isHostPrefix(r) {
			scope = "-host"
		}
		switch kind {
		case domain.OpAddRoute:
			return []string{"route", "-n", "add", scope, r.DstCIDR, r.Gateway}
		case domain.OpDelRoute:
			return []string{"route", "-n", "delete", scope, r.DstCIDR, r.Gateway}
		}
	}
	args := []string{"ip", "route"}
	switch kind {
	case domain.OpAddRoute:
		args = append(args, "add", r.DstCIDR)
		if r.Gateway != "" {
			args = append(args, "via", r.Gateway) // omit for an on-link tunnel default
		}
		args = append(args, "dev", r.Iface, "proto", "riftroute")
	case domain.OpDelRoute:
		args = append(args, "del", r.DstCIDR, "proto", "riftroute")
	}
	if r.Table != "" {
		args = append(args, "table", r.Table)
	}
	return args
}

func commandForRule(kind domain.OpKind, r domain.PolicyRule) []string {
	// A macOS PF route-to rule (identified by its route-to target) renders as an
	// anchor mutation for the plan preview; the provider applies the whole anchor.
	if r.RouteToIface != "" {
		target := r.RouteToIface
		if r.RouteToGW != "" {
			target = r.RouteToIface + " " + r.RouteToGW
		}
		if kind == domain.OpDelRule {
			return []string{"pf", "anchor", "riftroute:", "remove", r.Selector}
		}
		return []string{"pf", "anchor", "riftroute:", "pass", "out", "route-to", "(" + target + ")", r.Selector}
	}
	verb := "add"
	if kind == domain.OpDelRule {
		verb = "del"
	}
	args := []string{"ip", "rule", verb}
	args = append(args, strings.Fields(r.Selector)...) // e.g. "to 10.0.0.0/8"
	args = append(args, "lookup", r.Table, "priority", fmt.Sprint(r.Priority), "protocol", "riftroute")
	return args
}

func humanForRoute(kind domain.OpKind, r domain.Route) string {
	verb := "add"
	if kind == domain.OpDelRoute {
		verb = "del"
	}
	t := ""
	if r.Table != "" {
		t = " table " + r.Table
	}
	return fmt.Sprintf("%s %s via %s dev %s%s", verb, r.DstCIDR, r.Gateway, r.Iface, t)
}

func humanForRule(kind domain.OpKind, r domain.PolicyRule) string {
	if r.RouteToIface != "" { // macOS PF route-to
		verb := "route-to"
		if kind == domain.OpDelRule {
			verb = "remove route-to"
		}
		return fmt.Sprintf("%s %s → %s (pf)", verb, r.Selector, r.RouteToIface)
	}
	verb := "add rule"
	if kind == domain.OpDelRule {
		verb = "del rule"
	}
	return fmt.Sprintf("%s %s lookup %s priority %d", verb, r.Selector, r.Table, r.Priority)
}

// --- keys & helpers ---

// RouteKey identifies a route for set membership: family|table|dst|gateway|iface.
func RouteKey(r domain.Route) string {
	return string(r.Family) + "|" + r.Table + "|" + r.DstCIDR + "|" + r.Gateway + "|" + r.Iface
}

// RuleKey identifies a policy rule: priority|selector|table|family, plus the
// FULL macOS route-to target (iface AND gateway) when present. The gateway must
// be part of the identity: a VPN that re-handshakes on the same utun with a new
// peer gateway yields a rule that differs ONLY in RouteToGW — if the key ignored
// it, Reconcile would report "in sync" and the stale route-to would silently
// blackhole matched traffic at the dead next-hop. The suffix is omitted on
// Linux/fake, so their keys are unchanged.
func RuleKey(r domain.PolicyRule) string {
	k := fmt.Sprintf("%d|%s|%s|%s", r.Priority, r.Selector, r.Table, r.Family)
	if r.RouteToIface != "" {
		k += "|" + r.RouteToIface + "|" + r.RouteToGW
	}
	return k
}

func indexRoutes(rs []domain.ManagedRoute) map[string]domain.ManagedRoute {
	m := make(map[string]domain.ManagedRoute, len(rs))
	for _, r := range rs {
		m[RouteKey(r.Route)] = r
	}
	return m
}

func indexRules(rs []domain.ManagedRule) map[string]domain.ManagedRule {
	m := make(map[string]domain.ManagedRule, len(rs))
	for _, r := range rs {
		m[RuleKey(r.PolicyRule)] = r
	}
	return m
}

func ruleToPrefix(r domain.Rule) (netip.Prefix, domain.Family, bool) {
	switch r.Type {
	case domain.RuleCIDR:
		pfx, err := netip.ParsePrefix(r.Value)
		if err != nil {
			return netip.Prefix{}, "", false
		}
		return pfx, famOf(pfx.Addr()), true
	case domain.RuleIP:
		a, err := netip.ParseAddr(r.Value)
		if err != nil {
			return netip.Prefix{}, "", false
		}
		return netip.PrefixFrom(a, a.BitLen()), famOf(a), true
	default:
		return netip.Prefix{}, "", false
	}
}

func entryToPrefix(s string) (netip.Prefix, domain.Family, bool) {
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx, famOf(pfx.Addr()), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), famOf(a), true
	}
	return netip.Prefix{}, "", false
}

func resolveGateway(profileGW string, fam domain.Family, in DesiredInput) (netip.Addr, string, error) {
	iface := in.PhysIfaceV4
	auto := in.GatewayV4
	if fam == domain.FamilyV6 {
		iface, auto = in.PhysIfaceV6, in.GatewayV6
	}
	if profileGW == "" || profileGW == "auto" {
		if !auto.IsValid() {
			return netip.Addr{}, "", fmt.Errorf("no physical gateway for %s (cannot resolve gateway: auto)", fam)
		}
		return auto, iface, nil
	}
	a, err := netip.ParseAddr(profileGW)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("invalid gateway %q", profileGW)
	}
	if famOf(a) != fam {
		return netip.Addr{}, "", fmt.Errorf("gateway %s family does not match rule family %s", profileGW, fam)
	}
	return a, iface, nil
}

func vpnFor(fam domain.Family, in DesiredInput) (netip.Addr, string) {
	if fam == domain.FamilyV6 {
		return in.VPNGatewayV6, in.VPNIfaceV6
	}
	return in.VPNGatewayV4, in.VPNIfaceV4
}

func famOf(a netip.Addr) domain.Family {
	if a.Is6() {
		return domain.FamilyV6
	}
	return domain.FamilyV4
}

func protoFor(platform string) string {
	if platform == "linux" {
		return "riftroute"
	}
	return ""
}

func isHostPrefix(r domain.Route) bool {
	pfx, err := netip.ParsePrefix(r.DstCIDR)
	if err != nil {
		return false
	}
	return pfx.Bits() == pfx.Addr().BitLen()
}
