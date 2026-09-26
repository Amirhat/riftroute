package routing

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/Amirhat/riftroute/internal/domain"
)

// TunnelProfilePrefix tags the managed routes a tunnel owns ("tunnel:<name>")
// in the ProfileID slot, so ownership, explain, and the route table attribute
// them to the tunnel rather than to a profile.
const TunnelProfilePrefix = "tunnel:"

// TunnelInput is one managed tunnel's contribution to desired state.
type TunnelInput struct {
	Name string
	// Iface is the tunnel's interface while it is up; empty otherwise, in
	// which case its Routes are not installed (they stay on whatever path
	// they had — never blackholed into a dead interface).
	Iface string
	// V6 reports that the tunnel carries IPv6; its v6 routes are left out
	// (and reported blocked) without it.
	V6 bool
	// Routes are the CIDR/IP destinations sent into the tunnel.
	Routes []string
	// Bypass are the tunnel's own server addresses, pinned to the physical
	// gateway so its connection doesn't ride another VPN (via: direct).
	Bypass []netip.Addr
	// Servers are every address the tunnel's connection may go to — its
	// resolved remotes, pinned or not (via: default pins none). A route
	// containing one that no more specific route holds off the tunnel would
	// carry openvpn's own packets into the tunnel: it could never reconnect,
	// and the listed networks would blackhole — so that route is left out.
	// Bypass addresses count as servers whether or not they're listed here.
	Servers []netip.Addr
}

// TunnelPlan is what the managed tunnels contribute on the current network.
type TunnelPlan struct {
	// Routes are the tunnels' routes: each server pin via the physical
	// gateway, and each live tunnel's destinations on-link into its
	// interface (aggregated). No two share a destination.
	Routes []domain.ManagedRoute
	// Blocked are the listed routes left out, by tunnel name, and why.
	Blocked map[string][]domain.TunnelBlocked
	// nets are the destinations live tunnels route (exclude routes yield
	// inside them).
	nets []netip.Prefix
}

// claim is what routes a destination the tunnels hand out.
type claim struct {
	tunnel string
	pin    bool // a server pin rather than a destination into the tunnel
}

// PlanTunnels decides every tunnel route on the current network, and why the
// ones left out are. Each destination is claimed once — the kernel keeps one
// route per destination, and the guardrails refuse a WHOLE apply over a
// destination with two next hops, so one tunnel's routes must never be able to
// stall every other change. Server pins claim first (a tunnel's connection
// depends on them), then live tunnels in name order; tunnels that aren't up
// install nothing, but their routes are still checked against this network,
// so their status can say what would be left out.
//
// A tunnel that is down contributes no destination routes; a missing physical
// gateway drops only the pin. Neither is an error, so one tunnel's state can
// never make the rest of the desired set unappliable.
func PlanTunnels(in DesiredInput) TunnelPlan {
	tp := TunnelPlan{Blocked: map[string][]domain.TunnelBlocked{}}
	ts := append([]TunnelInput(nil), in.Tunnels...)
	sort.SliceStable(ts, func(i, j int) bool {
		if up := ts[i].Iface != ""; up != (ts[j].Iface != "") {
			return up
		}
		return ts[i].Name < ts[j].Name
	})

	taken := map[string]claim{}   // family|dst → who routes it
	held := map[netip.Addr]bool{} // servers a host route keeps out of the tunnels
	for _, t := range ts {
		tag := TunnelProfilePrefix + t.Name
		for _, a := range t.Bypass {
			fam := famOf(a)
			gw, iface, err := resolveGateway("auto", fam, in)
			if err != nil {
				continue
			}
			host := netip.PrefixFrom(a, a.BitLen())
			if _, occupied := in.Occupied[host.String()]; occupied {
				continue // someone else already pins the server; follow their route
			}
			held[a] = true
			if _, dup := taken[prefixKey(host)]; dup {
				continue // another tunnel pins the same server
			}
			taken[prefixKey(host)] = claim{tunnel: t.Name, pin: true}
			tp.add(domain.Route{DstCIDR: host.String(), Gateway: gw.String(), Iface: iface, Family: fam}, tag, in)
		}
		for _, a := range servers(t) {
			if _, occupied := in.Occupied[netip.PrefixFrom(a, a.BitLen()).String()]; occupied {
				held[a] = true
			}
		}
	}

	for _, t := range ts {
		tag := TunnelProfilePrefix + t.Name
		byFamily := map[domain.Family][]netip.Prefix{}
		for _, v := range t.Routes {
			pfx, fam, ok := entryToPrefix(v)
			if !ok {
				continue
			}
			pfx = pfx.Masked()
			why := ""
			if t.Iface != "" && fam == domain.FamilyV6 && !t.V6 {
				why = "the tunnel has no IPv6 address"
			}
			if why == "" {
				why = TunnelRouteBlock(pfx, in)
			}
			if c, ok := taken[prefixKey(pfx)]; why == "" && ok {
				why = c.reason(t.Name)
			}
			for _, a := range servers(t) {
				if why == "" && pfx.Contains(a) && !held[a] {
					why = fmt.Sprintf("contains the tunnel's own server %s — its connection would loop back into the tunnel", a)
				}
			}
			if why != "" {
				tp.Blocked[t.Name] = append(tp.Blocked[t.Name], domain.TunnelBlocked{Route: v, Reason: why})
				continue
			}
			byFamily[fam] = append(byFamily[fam], pfx)
		}
		if t.Iface == "" {
			continue // not up: nothing goes into it
		}
		for _, fam := range []domain.Family{domain.FamilyV4, domain.FamilyV6} {
			for _, pfx := range unclaimedAggregate(byFamily[fam], taken) {
				taken[prefixKey(pfx)] = claim{tunnel: t.Name}
				tp.nets = append(tp.nets, pfx)
				tp.add(domain.Route{DstCIDR: pfx.String(), Iface: t.Iface, Family: fam}, tag, in)
			}
		}
	}
	return tp
}

func (c claim) reason(tunnel string) string {
	switch {
	case c.pin && c.tunnel == tunnel:
		return "it's the tunnel's own server, pinned to your physical gateway"
	case c.pin:
		return fmt.Sprintf("it's tunnel %s's server, pinned to your physical gateway", c.tunnel)
	}
	return fmt.Sprintf("already routed into tunnel %s", c.tunnel)
}

// servers are the addresses a tunnel's connection may go to.
func servers(t TunnelInput) []netip.Addr {
	return append(append([]netip.Addr(nil), t.Bypass...), t.Servers...)
}

func (tp *TunnelPlan) add(rt domain.Route, tag string, in DesiredInput) {
	rt.Owner, rt.Proto, rt.Profile = domain.OwnerRiftRoute, protoFor(in.Platform), tag
	tp.Routes = append(tp.Routes, domain.ManagedRoute{Route: rt, ProfileID: tag, CreatedAt: in.Now})
}

// unclaimedAggregate aggregates a tunnel's destinations — never into a prefix
// something else already routes. Every listed destination was checked against
// the claims, so a claimed aggregate is a merge of halves; those go in as
// listed instead.
func unclaimedAggregate(prefixes []netip.Prefix, taken map[string]claim) []netip.Prefix {
	var out []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, agg := range Aggregate(prefixes) {
		parts := []netip.Prefix{agg}
		if _, ok := taken[prefixKey(agg)]; ok {
			parts = nil
			for _, p := range prefixes {
				if p.Bits() >= agg.Bits() && agg.Contains(p.Addr()) {
					parts = append(parts, p)
				}
			}
		}
		for _, p := range parts {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// place adds the plan's routes to a desired set (seen as addRoute keeps it),
// leaving out any whose exact destination the set already routes. Exclude
// routes yield inside live tunnels' networks, so a tunnel destination never
// meets one; a pin can meet a profile's host route for the same server, and
// that route then carries the server.
func (tp TunnelPlan) place(seen map[string]bool, routes *[]domain.ManagedRoute) {
	taken := map[string]bool{}
	for _, r := range *routes {
		taken[dstKey(r.Route)] = true
	}
	for _, r := range tp.Routes {
		if k := dstKey(r.Route); !taken[k] {
			taken[k] = true
			addRoute(seen, routes, r.Route, r.ProfileID, r.CreatedAt)
		}
	}
}

// Beside returns the rest of a desired set — what RiftRoute routes apart
// from its tunnels — with the plan's routes added, as BuildDesired would
// place them: main-table routes inside a live tunnel's networks yield to it,
// and a pin whose destination is already routed is left out.
func (tp TunnelPlan) Beside(others []domain.ManagedRoute) []domain.ManagedRoute {
	var out []domain.ManagedRoute
	seen := map[string]bool{}
	for _, o := range others {
		if pfx, err := netip.ParsePrefix(o.DstCIDR); err == nil && o.Table == "" && len(outsideTunnels([]netip.Prefix{pfx}, tp.nets)) == 0 {
			continue
		}
		if k := RouteKey(o.Route); !seen[k] {
			seen[k] = true
			out = append(out, o)
		}
	}
	tp.place(seen, &out)
	return out
}

// outsideTunnels drops exclude destinations that lie inside a tunnel's
// networks: a tunnel's destinations are explicitly behind it, and an exclude
// profile must not pull hosts back out — e.g. a wildcard domain whose DNS
// answers an internal host with its private address (gitlab.example.com →
// 192.168.70.42) would otherwise install a more specific direct route.
func outsideTunnels(prefixes, nets []netip.Prefix) []netip.Prefix {
	if len(nets) == 0 {
		return prefixes
	}
	out := prefixes[:0:0]
	for _, p := range prefixes {
		inside := false
		for _, n := range nets {
			if n.Bits() <= p.Bits() && n.Contains(p.Addr()) {
				inside = true
				break
			}
		}
		if !inside {
			out = append(out, p)
		}
	}
	return out
}

// TunnelRouteBlock says why a tunnel destination can't be installed on the
// current network, or "" if it can. Such a route is left out — reported by
// core.Service.TunnelStatuses — rather than failing the whole apply:
//   - it contains the physical gateway: it would cut the path to the router
//     (and the guardrails refuse the WHOLE apply over one);
//   - another owner routes that exact destination: the kernel keeps a single
//     route per destination, so the add would silently not happen.
//
// PlanTunnels adds what depends on the tunnels themselves: a destination
// claimed twice, a v6 route into a v4-only tunnel, a route that would carry
// the tunnel's own connection into it.
func TunnelRouteBlock(pfx netip.Prefix, in DesiredInput) string {
	gw := in.GatewayV4
	if pfx.Addr().Is6() {
		gw = in.GatewayV6
	}
	if gw.IsValid() && pfx.Contains(gw) {
		return fmt.Sprintf("contains your router %s — it would cut your connection", gw)
	}
	if iface, ok := in.Occupied[pfx.Masked().String()]; ok {
		return fmt.Sprintf("already routed via %s by something else (another VPN or the system)", iface)
	}
	return ""
}

// prefixKey is dstKey for a main-table prefix.
func prefixKey(p netip.Prefix) string {
	return string(famOf(p.Addr())) + "||" + p.Masked().String()
}
