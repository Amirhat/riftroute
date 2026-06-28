// Package routing is the engine: it builds desired state from enabled profiles,
// reconciles it against actual managed routes into an ordered plan WITH a
// precomputed inverse (the spine of the Apply Protocol, spec §2.2), and provides
// a longest-prefix-match simulator for route-explain and conflict detection
// (spec §5.2/§7.2). Pure logic — no kernel, no I/O — so it is exhaustively
// testable against the fake provider.
package routing

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// DesiredInput is everything the builder needs to derive desired managed routes.
type DesiredInput struct {
	Profiles    []domain.Profile
	GatewayV4   netip.Addr // resolved physical gateway (VPN-independent)
	GatewayV6   netip.Addr
	PhysIfaceV4 string
	PhysIfaceV6 string
	Platform    string // "darwin" | "linux" | "fake"
	Now         time.Time
}

// BuildDesired computes the managed routes implied by the enabled profiles.
// M2 covers exclude mode + Model A: each cidr/ip rule becomes a bypass route via
// the physical gateway, more specific than the VPN default. include mode and
// domain/asn/country/app rules are deferred (M4/M5) and skipped here.
func BuildDesired(in DesiredInput) ([]domain.ManagedRoute, error) {
	// Higher priority wins on a key collision.
	profs := append([]domain.Profile{}, in.Profiles...)
	sort.SliceStable(profs, func(i, j int) bool { return profs[i].Priority > profs[j].Priority })

	seen := map[string]bool{}
	var out []domain.ManagedRoute
	for _, p := range profs {
		if !p.Enabled || p.Mode != domain.ModeExclude {
			continue
		}
		for _, r := range p.Rules {
			pfx, fam, ok := ruleToPrefix(r)
			if !ok {
				continue // domain/asn/country/app: handled in later milestones
			}
			gw, iface, err := resolveGateway(p.Gateway, fam, in)
			if err != nil {
				return nil, fmt.Errorf("profile %q: %w", p.Name, err)
			}
			rt := domain.Route{
				DstCIDR: pfx.Masked().String(),
				Gateway: gw.String(),
				Iface:   iface,
				Family:  fam,
				Owner:   domain.OwnerRiftRoute,
				Proto:   protoFor(in.Platform),
				Profile: p.ID,
			}
			k := RouteKey(rt)
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, domain.ManagedRoute{Route: rt, ProfileID: p.ID, CreatedAt: in.Now})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].DstCIDR < out[j].DstCIDR })
	return out, nil
}

// Reconcile diffs desired against actual managed routes and returns an ordered
// plan plus its exact inverse. Adds run before deletes so a bypass exists before
// any stale route is removed (connectivity-preserving). The inverse is the
// reverse-ordered, action-flipped op list — rollback replays it to undo exactly.
func Reconcile(desired, actual []domain.ManagedRoute, platform string) domain.Plan {
	desiredByKey := indexByKey(desired)
	actualByKey := indexByKey(actual)

	var ops []domain.PlanOp
	for _, d := range desired {
		if _, ok := actualByKey[RouteKey(d.Route)]; !ok {
			ops = append(ops, makeOp(domain.OpAddRoute, d, platform))
		}
	}
	for _, a := range actual {
		if _, ok := desiredByKey[RouteKey(a.Route)]; !ok {
			ops = append(ops, makeOp(domain.OpDelRoute, a, platform))
		}
	}
	return domain.Plan{Ops: ops, Inverse: invert(ops, platform)}
}

// invert produces the rollback plan: reverse order, add<->del.
func invert(ops []domain.PlanOp, platform string) []domain.PlanOp {
	inv := make([]domain.PlanOp, 0, len(ops))
	for i := len(ops) - 1; i >= 0; i-- {
		op := ops[i]
		mr := domain.ManagedRoute{}
		if op.Route != nil {
			mr = *op.Route
		}
		switch op.Kind {
		case domain.OpAddRoute:
			inv = append(inv, makeOp(domain.OpDelRoute, mr, platform))
		case domain.OpDelRoute:
			inv = append(inv, makeOp(domain.OpAddRoute, mr, platform))
		}
	}
	return inv
}

func makeOp(kind domain.OpKind, mr domain.ManagedRoute, platform string) domain.PlanOp {
	cp := mr
	return domain.PlanOp{
		Kind:    kind,
		Route:   &cp,
		Command: commandFor(kind, mr.Route, platform),
		Human:   humanFor(kind, mr.Route),
	}
}

// commandFor returns the exact arg-array a real provider would exec (no shell),
// shown verbatim in dry-run and the audit log (spec §2.2/§7.7).
func commandFor(kind domain.OpKind, r domain.Route, platform string) []string {
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
	// linux / fake (illustrative)
	switch kind {
	case domain.OpAddRoute:
		return []string{"ip", "route", "add", r.DstCIDR, "via", r.Gateway, "dev", r.Iface, "proto", "riftroute"}
	case domain.OpDelRoute:
		return []string{"ip", "route", "del", r.DstCIDR, "proto", "riftroute"}
	}
	return nil
}

func humanFor(kind domain.OpKind, r domain.Route) string {
	verb := "add"
	if kind == domain.OpDelRoute {
		verb = "del"
	}
	return fmt.Sprintf("%s %s via %s dev %s", verb, r.DstCIDR, r.Gateway, r.Iface)
}

// --- helpers ---

// RouteKey identifies a route for set membership: family|dst|gateway|iface.
func RouteKey(r domain.Route) string {
	return string(r.Family) + "|" + r.DstCIDR + "|" + r.Gateway + "|" + r.Iface
}

func indexByKey(rs []domain.ManagedRoute) map[string]domain.ManagedRoute {
	m := make(map[string]domain.ManagedRoute, len(rs))
	for _, r := range rs {
		m[RouteKey(r.Route)] = r
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
