package routing

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/Amirhat/riftroute/internal/domain"
)

// TunnelProfilePrefix tags the managed routes a tunnel owns ("tunnel:<name>")
// in the ProfileID slot, so ownership, explain, and the route table attribute
// them to the tunnel rather than to a profile.
const TunnelProfilePrefix = "tunnel:"

// TunnelInput is one managed tunnel's contribution to desired state.
type TunnelInput struct {
	Name string
	// Iface is the tunnel's interface while it is connected; empty
	// otherwise, in which case its Routes are not installed — they take
	// whatever path they'd take without it — unless it's set to Block.
	Iface string
	// V6 reports that the tunnel carries IPv6; its v6 routes are left out
	// (and reported blocked) without it — refused, with Block.
	V6 bool
	// Block: the tunnel is set to block while it's down, and should be up
	// (the manager sets it only then). While Iface is empty, each of its
	// destinations gets a reject route instead of going into it, so none
	// leaves another way; while it's up, so does a v6 destination it can't
	// carry.
	Block bool
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
	// gateway, each live tunnel's destinations on-link into its interface,
	// and each blocking tunnel's reject routes (aggregated). No two share a
	// destination.
	Routes []domain.ManagedRoute
	// Blocked are the listed routes left out, by tunnel name, and why.
	Blocked map[string][]domain.TunnelBlocked
	// Narrowed are the listed routes installed with parts kept out, by
	// tunnel name, and what and why (see carve).
	Narrowed map[string][]domain.TunnelNarrowed
	// nets are the destinations live tunnels route or blocking tunnels
	// refuse (exclude routes yield inside them, include rules are cut
	// around them).
	nets []netip.Prefix
}

// claim is what routes a destination the tunnels hand out.
type claim struct {
	tunnel string
	pin    bool // a server pin rather than a destination into the tunnel
	refuse bool // a reject route: the tunnel is down and set to block
}

// PlanTunnels decides every tunnel route on the current network, and why the
// ones left out are. Each destination is claimed once — the kernel keeps one
// route per destination, and the guardrails refuse a WHOLE apply over a
// destination with two next hops, so one tunnel's routes must never be able to
// stall every other change. Server pins claim first (a tunnel's connection
// depends on them), then live tunnels in name order, then blocking ones;
// other tunnels that aren't up install nothing, but their routes are still
// checked against this network, so their status can say what would be left
// out.
//
// A tunnel that is down contributes no destination routes — unless it's set
// to block (TunnelInput.Block), when each destination gets a reject route,
// through the same checks: a reject route holding the router or a tunnel's
// server cuts the connection as surely as a route into a tunnel. A missing
// physical gateway drops only the pin. None of these is an error, so one
// tunnel's state can never make the rest of the desired set unappliable.
func PlanTunnels(in DesiredInput) TunnelPlan {
	tp := TunnelPlan{Blocked: map[string][]domain.TunnelBlocked{}, Narrowed: map[string][]domain.TunnelNarrowed{}}
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
			noV6 := t.Iface != "" && fam == domain.FamilyV6 && !t.V6
			if noV6 && !t.Block {
				why = "the tunnel has no IPv6 address"
			}
			if why == "" {
				why = TunnelRouteBlock(pfx, in)
			}
			if c, ok := taken[prefixKey(pfx)]; why == "" && ok {
				why = c.reason(t.Name)
			}
			for _, n := range in.Tailscale {
				if why == "" && n.Addr().Is4() == pfx.Addr().Is4() && n.Bits() <= pfx.Bits() && n.Contains(pfx.Addr()) {
					why = fmt.Sprintf("it's inside %s, which Tailscale routes — left to it", n)
				}
			}
			parts := []netip.Prefix{pfx}
			if keep := keepOut(pfx, t, ts, held, in, false); why == "" && len(keep) > 0 {
				// What it holds that mustn't go into the tunnel is kept out
				// (with the network someone routes it in); the rest goes in.
				others := othersInside(pfx, t.Name, ts, in.Occupied)
				var except []domain.TunnelExcept
				parts, except = carve(pfx, keep, others, taken)
				if t.Block && (len(parts) == 0 || len(parts) > maxCarved) {
					// Set to block: never in the clear. Only what keeps the
					// connection (the router's network, the servers) stays
					// out; resolvers and anchors inside go in, or are refused.
					parts, except = carve(pfx, keepOut(pfx, t, ts, held, in, true), others, taken)
				}
				switch {
				case len(parts) == 0:
					why = "nothing would be left once these are kept out: " + exceptText(except)
				case len(parts) > maxCarved:
					why = fmt.Sprintf("it would take %d routes to go around %s; list narrower networks", len(parts), exceptText(except))
				default:
					tp.Narrowed[t.Name] = append(tp.Narrowed[t.Name], domain.TunnelNarrowed{Route: v, Except: except})
				}
			}
			if why == "" && noV6 {
				// Set to block: refused rather than left to leak — a name
				// with both addresses would otherwise go out over v6.
				why = "the tunnel has no IPv6 address, so it's refused (block when down)"
				byFamily[fam] = append(byFamily[fam], parts...)
			}
			if why != "" {
				tp.Blocked[t.Name] = append(tp.Blocked[t.Name], domain.TunnelBlocked{Route: v, Reason: why})
				continue
			}
			byFamily[fam] = append(byFamily[fam], parts...)
		}
		if t.Iface == "" && !t.Block {
			continue // not up: nothing goes into it
		}
		for _, fam := range []domain.Family{domain.FamilyV4, domain.FamilyV6} {
			// Up: into the tunnel, but for v6 it can't carry. Down (and set
			// to block): all of it refused.
			refuse := t.Iface == "" || (fam == domain.FamilyV6 && !t.V6)
			for _, pfx := range unclaimedAggregate(byFamily[fam], taken) {
				taken[prefixKey(pfx)] = claim{tunnel: t.Name, refuse: refuse}
				tp.nets = append(tp.nets, pfx)
				if refuse {
					tp.add(domain.Route{DstCIDR: pfx.String(), Family: fam, Reject: true}, tag, in)
				} else {
					tp.add(domain.Route{DstCIDR: pfx.String(), Iface: t.Iface, Family: fam}, tag, in)
				}
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
	case c.refuse:
		return fmt.Sprintf("already blocked for tunnel %s while it's down", c.tunnel)
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

// aroundTunnels is outsideTunnels for include mode. An include rule is a
// policy rule (Linux) or a PF route-to rule (macOS), matched before the
// routing table the tunnels' routes are in: one merely containing a tunnel's
// network still captures its traffic, where an exclude route would lose to
// the tunnel's more specific route. So a prefix inside a live tunnel's
// networks is dropped, and one containing some is split around them.
func aroundTunnels(prefixes, nets []netip.Prefix) []netip.Prefix {
	if len(nets) == 0 {
		return prefixes
	}
	var out []netip.Prefix
	for _, p := range prefixes {
		out = append(out, subtractNets(p.Masked(), nets)...)
	}
	return out
}

// subtractNets returns the part of p outside every one of nets, as prefixes.
func subtractNets(p netip.Prefix, nets []netip.Prefix) []netip.Prefix {
	for _, n := range nets {
		switch {
		case n.Addr().Is4() != p.Addr().Is4():
		case n.Bits() <= p.Bits() && n.Contains(p.Addr()):
			return nil // p lies inside n
		case p.Bits() < n.Bits() && p.Contains(n.Addr()):
			lo, hi := halves(p)
			return append(subtractNets(lo, nets), subtractNets(hi, nets)...)
		}
	}
	return []netip.Prefix{p}
}

// halves splits p into its two halves.
func halves(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits() + 1
	raw := p.Masked().Addr().AsSlice()
	lo := netip.PrefixFrom(p.Masked().Addr(), bits)
	raw[p.Bits()/8] |= 0x80 >> (p.Bits() % 8)
	hi, _ := netip.AddrFromSlice(raw)
	return lo, netip.PrefixFrom(hi, bits)
}

// RulesBeside returns the rules RiftRoute's include profiles installed,
// placed beside the tunnels as BuildDesired would place them: a destination
// rule yields to live tunnels' networks (aroundTunnels) — the tunnel-only
// apply's counterpart of Beside. An app's selector can't be split; it is kept
// as it is (see AppRuleCaptures).
func (tp TunnelPlan) RulesBeside(rules []domain.ManagedRule) []domain.ManagedRule {
	if len(tp.nets) == 0 {
		return rules
	}
	var out []domain.ManagedRule
	seen := map[string]bool{}
	add := func(r domain.ManagedRule) {
		if k := RuleKey(r.PolicyRule); !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}
	for _, r := range rules {
		pfx, ok := ruleDestination(r.PolicyRule)
		if !ok {
			add(r)
			continue
		}
		parts := aroundTunnels([]netip.Prefix{pfx}, tp.nets)
		if len(parts) == 1 && parts[0] == pfx.Masked() {
			add(r) // untouched, as the kernel spells it
			continue
		}
		for _, p := range parts {
			nr := r
			nr.Selector = "to " + p.String()
			add(nr)
		}
	}
	return out
}

// ruleDestination is the destination a rule selects by, when that is all
// it selects by.
func ruleDestination(r domain.PolicyRule) (netip.Prefix, bool) {
	dst, ok := strings.CutPrefix(r.Selector, "to ")
	if !ok || strings.ContainsRune(dst, ' ') {
		return netip.Prefix{}, false
	}
	pfx, _, ok := entryToPrefix(dst)
	return pfx, ok
}

// AppRuleCaptures reports, by tunnel name, the live tunnels' destinations that
// include-mode app rules still capture: such a rule selects an app's (or a
// user's) traffic whatever its destination, before the routing table the
// tunnel's routes are in — and unlike a destination rule, it can't yield
// around them. rules are the policy rules RiftRoute installed.
func AppRuleCaptures(tp TunnelPlan, rules []domain.ManagedRule) map[string][]domain.TunnelBlocked {
	var apps []domain.PolicyRule
	for _, r := range rules {
		if _, ok := ruleDestination(r.PolicyRule); !ok {
			apps = append(apps, r.PolicyRule)
		}
	}
	if len(apps) == 0 {
		return nil
	}
	out := map[string][]domain.TunnelBlocked{}
	for _, t := range tp.Routes {
		name, ok := strings.CutPrefix(t.ProfileID, TunnelProfilePrefix)
		if !ok || t.Gateway != "" {
			continue // a pin goes via the physical gateway, not into the tunnel
		}
		for _, a := range apps {
			if a.Family != t.Family {
				continue
			}
			into := "your VPN (table " + a.Table + ")"
			if a.RouteToIface != "" {
				into = a.RouteToIface
			}
			out[name] = append(out[name], domain.TunnelBlocked{
				Route:  t.DstCIDR,
				Reason: fmt.Sprintf("the include-mode app rule %q sends that traffic into %s, to this network too", a.Selector, into),
			})
		}
	}
	return out
}

// TunnelRouteBlock says why a tunnel destination can't be installed on the
// current network, or "" if it can: another owner routes that exact
// destination (the kernel keeps a single route per destination, so the add
// would silently not happen). Such a route is left out — reported by
// core.Service.TunnelStatuses — rather than failing the whole apply.
//
// What a destination holds that mustn't go into a tunnel isn't a reason to
// leave it out: it's kept out of it instead (keepOut, carve). PlanTunnels
// adds what depends on the tunnels themselves: a destination claimed twice,
// a v6 route into a v4-only tunnel.
func TunnelRouteBlock(pfx netip.Prefix, in DesiredInput) string {
	if iface, ok := in.Occupied[pfx.Masked().String()]; ok {
		return fmt.Sprintf("already routed via %s by something else (another VPN or the system)", iface)
	}
	return ""
}

// keptOut is an address a tunnel route mustn't carry, and why; net, when
// valid, is the network kept out with it (on that interface): the router's
// LAN.
type keptOut struct {
	addr netip.Addr
	why  string
	net  netip.Prefix
	on   string
}

// keepOut lists what pfx holds that mustn't go into tunnel t on the current
// network:
//   - the router: the path to it would be cut;
//   - a DNS server in use: every name lookup would go into the tunnel (e.g.
//     10.0.0.0/8 while the main VPN's resolver is 10.255.255.1);
//   - an address RiftRoute probes: the watchdog guarding every change would
//     probe through the tunnel;
//   - a tunnel's server nothing holds off the tunnels (a pin, someone else's
//     host route): its own would loop back into itself, another's would ride
//     this one — two via-default tunnels each carrying the other's server
//     both stall.
func keepOut(pfx netip.Prefix, t TunnelInput, ts []TunnelInput, held map[netip.Addr]bool, in DesiredInput, essential bool) []keptOut {
	var out []keptOut
	gw, lan, on := in.GatewayV4, in.PhysNetV4, in.PhysIfaceV4
	if pfx.Addr().Is6() {
		gw, lan, on = in.GatewayV6.WithZone(""), in.PhysNetV6, in.PhysIfaceV6
	}
	if gw.IsValid() && pfx.Contains(gw) {
		k := keptOut{addr: gw, why: "your router " + gw.String()}
		if lan.IsValid() && lan.Contains(gw) {
			// Its network (a destination inside it: all of it), so the
			// local network stays local.
			k.net, k.on = lan.Masked(), on
			if lan.Bits() <= pfx.Bits() {
				k.net = pfx
			}
		}
		out = append(out, k)
	}
	resolvers := map[bool]int{} // by family
	for _, a := range in.DNSServers {
		if essential || resolvers[a.Is4()] >= maxKeptResolvers {
			continue
		}
		resolvers[a.Is4()]++
		if pfx.Contains(a) {
			out = append(out, keptOut{addr: a, why: "your DNS server " + a.String()})
		}
	}
	for _, a := range in.Anchors {
		if !essential && pfx.Contains(a) {
			out = append(out, keptOut{addr: a, why: a.String() + ", which RiftRoute probes to check a change kept you online"})
		}
	}
	for _, o := range ts {
		for _, a := range servers(o) {
			if !pfx.Contains(a) || held[a] {
				continue
			}
			if o.Name == t.Name {
				out = append(out, keptOut{addr: a, why: "the tunnel's own server " + a.String()})
			} else {
				out = append(out, keptOut{addr: a, why: fmt.Sprintf("tunnel %s's server %s", o.Name, a)})
			}
		}
	}
	// One address, said once: the first reason (the router before the
	// anchor that probes it).
	seen := map[netip.Addr]bool{}
	return slices.DeleteFunc(out, func(k keptOut) bool {
		dup := seen[k.addr]
		seen[k.addr] = true
		return dup
	})
}

// maxCarved bounds the routes one listed destination may become.
const maxCarved = 1024

// maxKeptResolvers is how many of a family's resolvers (the first, as the
// system lists them) are kept out of tunnel routes: a network that names
// dozens, scattered over a destination, can't carve it past maxCarved.
const maxKeptResolvers = 8

// routeInside is a route someone else has inside a tunnel destination:
// another owner's (via its interface) or another tunnel's.
type routeInside struct {
	net netip.Prefix
	via string
}

// othersInside lists the routes inside pfx (more specific) that aren't
// tunnel name's: the kernel's other owners', and the other tunnels' listed
// destinations.
func othersInside(pfx netip.Prefix, name string, ts []TunnelInput, occupied map[string]string) []routeInside {
	in := func(q netip.Prefix) bool {
		return q.Addr().Is4() == pfx.Addr().Is4() && q.Bits() > pfx.Bits() && pfx.Contains(q.Addr())
	}
	var out []routeInside
	for k, via := range occupied {
		if q, err := netip.ParsePrefix(k); err == nil && in(q.Masked()) {
			out = append(out, routeInside{q.Masked(), via})
		}
	}
	for _, o := range ts {
		if o.Name == name {
			continue
		}
		for _, v := range o.Routes {
			if q, _, ok := entryToPrefix(v); ok && in(q.Masked()) {
				out = append(out, routeInside{q.Masked(), "tunnel " + o.Name})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].net.String() < out[j].net.String() })
	return out
}

// carve returns pfx without what keep holds, and what was kept out and why.
// Each address goes with the narrowest route someone else has inside pfx
// that holds it — the router with its network — or alone. The rest goes
// in, but for parts inside a route someone else has inside pfx, or one a
// tunnel claims: those stay theirs, as they were with pfx whole (a part
// more specific than their route would take its traffic).
func carve(pfx netip.Prefix, keep []keptOut, others []routeInside, taken map[string]claim) ([]netip.Prefix, []domain.TunnelExcept) {
	reasons := map[netip.Prefix][]string{}
	var holes []netip.Prefix
	for _, k := range keep {
		hole, why := netip.PrefixFrom(k.addr, k.addr.BitLen()), k.why
		holders := others
		if k.net.IsValid() {
			// The router: its whole network stays on the physical interface.
			hole, why, holders = k.net, fmt.Sprintf("the network of %s, on %s", k.why, k.on), nil
		}
		found := false
		for _, o := range holders {
			if !o.net.Contains(k.addr) || (found && o.net.Bits() <= hole.Bits()) {
				continue
			}
			hole, found = o.net, true
			if o.net.IsSingleIP() {
				why = fmt.Sprintf("%s, routed via %s", k.why, o.via)
			} else {
				why = fmt.Sprintf("the network of %s, via %s", k.why, o.via)
			}
		}
		if _, ok := reasons[hole]; !ok {
			holes = append(holes, hole)
		}
		reasons[hole] = append(reasons[hole], why)
	}
	var parts []netip.Prefix
	for _, p := range subtractNets(pfx, holes) {
		theirs := false
		for _, o := range others {
			theirs = theirs || o.net.Bits() <= p.Bits() && o.net.Contains(p.Addr())
		}
		if _, claimed := taken[prefixKey(p)]; !theirs && !claimed {
			parts = append(parts, p)
		}
	}
	sort.Slice(holes, func(i, j int) bool { return holes[i].Addr().Less(holes[j].Addr()) })
	// One kept out inside another is said with the outermost.
	var outer []netip.Prefix
	for _, h := range holes {
		top := h
		for _, o := range holes {
			if o.Bits() < top.Bits() && o.Contains(h.Addr()) {
				top = o
			}
		}
		if top != h {
			reasons[top] = append(reasons[top], reasons[h]...)
		} else {
			outer = append(outer, h)
		}
	}
	except := make([]domain.TunnelExcept, 0, len(outer))
	for _, h := range outer {
		net := h.String()
		if h.IsSingleIP() {
			net = h.Addr().String()
		}
		except = append(except, domain.TunnelExcept{Net: net, Reason: strings.Join(reasons[h], "; ")})
	}
	return parts, except
}

// exceptText lists what was kept out of a route.
func exceptText(except []domain.TunnelExcept) string {
	var out []string
	for _, e := range except {
		out = append(out, e.Net+" ("+e.Reason+")")
	}
	return strings.Join(out, ", ")
}

// Verified is what VerifyRoutes found.
type Verified struct {
	// Kept is owned as the kernel really holds it: the plan's "actual".
	Kept []domain.ManagedRoute
	// Missing are routes desired still wants that the kernel no longer has
	// (not in Kept): a reconcile puts them back.
	Missing []domain.ManagedRoute
	// Taken are wanted routes the kernel doesn't have because another route
	// holds their destination and leaves them no place (Installed.Outranked)
	// — another program's. They stay in Kept: RiftRoute never replaces a
	// route it didn't make, and adding beside it only meets "File exists".
	// Once that route goes, they're Missing. A route that would lose to
	// RiftRoute's (a higher metric on Linux) doesn't take it: that's Missing.
	Taken []domain.ManagedRoute
}

// VerifyRoutes checks owned against the kernel: a route desired still wants
// that the kernel doesn't have is Missing, left out of Kept, so a reconcile
// against Kept puts it back. A tunnel's routes vanish with its interface
// (openvpn re-creates its tun under the same name), and another program — a
// VPN client tidying the table — can delete any of RiftRoute's. Desired and
// the ownership map still agree, so nothing else would re-add them, and
// drift would read "in sync". Missing routes desired no longer wants stay,
// so the plan's (idempotent) delete clears their records.
//
// held are RouteKeys to keep regardless: another program keeps removing
// them, and putting them back would only fight it (the Apply Protocol's live
// repair holds them for a while). A tunnel's routes are never held: its
// routes, its pins and block mode's reject routes keep its promise, and are
// put back every time. only, when set, limits the check to the routes it
// accepts (a tunnel's apply carries the others over as recorded). read
// returns one family's kernel table. It runs once per family holding a
// wanted route; a failed read changes nothing.
func VerifyRoutes(owned, desired []domain.ManagedRoute, read func(domain.Family) ([]domain.Route, error), held map[string]bool, only func(domain.ManagedRoute) bool) Verified {
	wanted := indexRoutes(desired)
	kernel := map[domain.Family]*Installed{}
	var v Verified
	for _, o := range owned {
		var in *Installed
		if _, ok := wanted[RouteKey(o.Route)]; ok && (only == nil || only(o)) {
			var read1 bool
			if in, read1 = kernel[o.Family]; !read1 {
				if rs, err := read(o.Family); err == nil {
					in = IndexInstalled(rs)
				}
				kernel[o.Family] = in // nil after a failed read: trust the records
			}
		}
		switch {
		case in == nil || in.Has(o.Route):
		case in.Outranked(o.Route):
			v.Taken = append(v.Taken, o)
		case held[RouteKey(o.Route)] && !IsTunnelRoute(o):
		default:
			v.Missing = append(v.Missing, o)
			continue
		}
		v.Kept = append(v.Kept, o)
	}
	return v
}

// IsTunnelRoute says whether a route is one of a tunnel's (its routes, its
// server pins, a tunnel-mode profile's).
func IsTunnelRoute(o domain.ManagedRoute) bool {
	return strings.HasPrefix(o.ProfileID, TunnelProfilePrefix)
}

// Installed indexes a kernel table read, to tell which routes are really
// there.
type Installed struct {
	routes map[string]bool
	// lowest is, per destination, the lowest metric among the routes to it
	// (scoped ones aside: Outranked).
	lowest map[string]int
}

// IndexInstalled indexes kernel routes. Clone entries don't count: they are
// the kernel's cache, not routes anyone added.
func IndexInstalled(kernel []domain.Route) *Installed {
	in := &Installed{routes: map[string]bool{}, lowest: map[string]int{}}
	for _, k := range kernel {
		if k.Cloned {
			continue
		}
		dst := maskedDstKey(k)
		if !k.Scoped { // macOS's per-interface routes carry only traffic bound to their interface
			if m, ok := in.lowest[dst]; !ok || k.Metric < m {
				in.lowest[dst] = k.Metric
			}
		}
		if k.Reject {
			in.routes[dst+"|reject"] = true
			continue
		}
		in.routes[dst+"|dev "+k.Iface] = true
		if k.Gateway != "" {
			in.routes[dst+"|via "+gatewayKey(k.Gateway)] = true
		}
	}
	return in
}

// Has reports whether the kernel holds r: its destination through its
// gateway — or, for an on-link route, on its interface; refused, for a
// reject route.
func (in *Installed) Has(r domain.Route) bool {
	if r.Reject {
		return in.routes[maskedDstKey(r)+"|reject"]
	}
	if r.Gateway != "" {
		return in.routes[maskedDstKey(r)+"|via "+gatewayKey(r.Gateway)]
	}
	return in.routes[maskedDstKey(r)+"|dev "+r.Iface]
}

// Outranked reports whether the kernel holds a route to r's destination
// (same family, table and masked prefix) that leaves r no place: one whose
// metric is no higher than r's. Linux keeps routes to one destination side
// by side when their metrics differ, the lowest winning, and answers "File
// exists" only to one of the same metric; a higher-metric route (a
// NetworkManager or DHCP fallback) loses to r, and r goes in beside it.
// Elsewhere there's one route per destination, and no metrics: any counts.
// Call it for a route the kernel doesn't hold (Has): every route to its
// destination is then someone else's.
func (in *Installed) Outranked(r domain.Route) bool {
	lowest, ok := in.lowest[maskedDstKey(r)]
	return ok && lowest <= effectiveMetric(r)
}

// effectiveMetric is the metric the kernel gives r: its own, else Linux's
// default for the family (IPv6 routes added without one get 1024).
func effectiveMetric(r domain.Route) int {
	switch {
	case r.Metric > 0:
		return r.Metric
	case r.Family == domain.FamilyV6:
		return 1024
	}
	return 0
}

// SameGateway reports whether two spellings name the same gateway (see
// gatewayKey).
func SameGateway(a, b string) bool { return gatewayKey(a) == gatewayKey(b) }

// KernelKey identifies a route as a table read lists it — the destination
// masked, the gateway in one spelling (gatewayKey) — so a route RiftRoute
// recorded matches its own entry in the kernel's table. Its RouteKey may not:
// on macOS a gateway is recorded as `route get` prints it (fe80::1%en0), and
// the table lists it without the zone or in KAME form (fe80:4::1).
func KernelKey(r domain.Route) string {
	k := maskedDstKey(r) + "|" + gatewayKey(r.Gateway) + "|" + r.Iface
	if r.Reject {
		k += "|reject"
	}
	return k
}

// gatewayKey spells a gateway one way whichever source it came from: a
// link-local one may carry a zone ("fe80::1%en0") or, read from the macOS
// RIB, its scope embedded in the address (KAME's "fe80:4::1").
func gatewayKey(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return s
	}
	a = a.Unmap().WithZone("")
	if a.Is6() && a.IsLinkLocalUnicast() {
		raw := a.As16()
		raw[2], raw[3] = 0, 0
		a = netip.AddrFrom16(raw)
	}
	return a.String()
}

// maskedDstKey is dstKey with the destination masked, as kernels list it.
func maskedDstKey(r domain.Route) string {
	if pfx, err := netip.ParsePrefix(r.DstCIDR); err == nil {
		r.DstCIDR = pfx.Masked().String()
	}
	return dstKey(r)
}

// prefixKey is dstKey for a main-table prefix.
func prefixKey(p netip.Prefix) string {
	return string(famOf(p.Addr())) + "||" + p.Masked().String()
}
