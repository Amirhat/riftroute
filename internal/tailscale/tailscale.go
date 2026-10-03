// Package tailscale recognizes a Tailscale running beside RiftRoute
// (docs/tailscale.md) from the kernel's state alone — its interface, the
// networks it routes, whether its exit node is on — so RiftRoute can keep
// out of its way. RiftRoute never runs or changes it.
package tailscale

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/Amirhat/riftroute/internal/domain"
)

// Tailscale's own ranges, and MagicDNS.
var (
	CGNAT    = netip.MustParsePrefix("100.64.0.0/10")
	ULA      = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	MagicDNS = netip.MustParseAddr("100.100.100.100")
)

// LinuxTable is the routing table Tailscale keeps its routes in on Linux,
// looked up — by its rule at 5270 — before the main table.
const LinuxTable = "52"

// maxNetworks bounds the networks counted beyond its two ranges (the
// widest first): a tailnet's thousand App Connector /32s cost nothing.
const maxNetworks = 256

// Find picks Tailscale's interface among ifaces, given the resolvers in use:
//   - tailscale0 (Linux: its name);
//   - a utun (macOS) holding an address in its IPv6 range — Tailscale and
//     Headscale give every node one;
//   - a utun holding an address in its IPv4 range, with MagicDNS among the
//     resolvers. A CGNAT address alone isn't Tailscale's: Cloudflare WARP
//     and NetBird use that space too.
//
// sure: by name or by its IPv6 address. Only then are the routes into it its
// networks; otherwise only its own two ranges are. Among several such utuns
// (WARP's beside a Tailscale with no IPv6 address), the one routes (when
// given) send MagicDNS into wins, else the first.
func Find(ifaces []domain.Iface, routes []domain.Route, resolvers []netip.Addr) (name string, sure, ok bool) {
	magic := slices.Contains(resolvers, MagicDNS)
	magicVia := magicDNSIface(routes)
	for _, i := range ifaces {
		if !i.Up {
			continue
		}
		if strings.HasPrefix(i.Name, "tailscale") {
			return i.Name, true, true
		}
		if !strings.HasPrefix(i.Name, "utun") {
			continue
		}
		v4 := false
		for _, a := range i.Addrs {
			p, err := netip.ParsePrefix(a)
			switch {
			case err != nil:
			case ULA.Contains(p.Addr()):
				return i.Name, true, true
			case CGNAT.Contains(p.Addr()):
				v4 = true
			}
		}
		if v4 && magic {
			if !ok || i.Name == magicVia {
				name, ok = i.Name, true
			}
		}
	}
	return name, false, ok
}

// magicDNSIface is the interface the main table sends MagicDNS into: its
// most specific route's, as the kernel picks (a default doesn't count), or "".
func magicDNSIface(routes []domain.Route) string {
	via, bits := "", 0
	for _, r := range routes {
		p, err := netip.ParsePrefix(r.DstCIDR)
		if err != nil || r.Scoped || r.Table != "" || r.Reject || !p.Contains(MagicDNS) || p.Bits() <= bits {
			continue
		}
		via, bits = r.Iface, p.Bits()
	}
	return via
}

// Detect finds Tailscale (Find) and, from routes (the main table's, and on
// Linux table 52's), what it routes and whether its exit node is on (a
// default route into it). ok is false without one.
func Detect(ifaces []domain.Iface, routes []domain.Route, resolvers []netip.Addr) (st domain.TailscaleStatus, ok bool) {
	name, sure, ok := Find(ifaces, routes, resolvers)
	if !ok {
		return st, false
	}
	st.Iface = name
	nets := []netip.Prefix{CGNAT, ULA}
	var extra []netip.Prefix
	halves := 0
	for _, r := range routes {
		// Not a scoped route (macOS keeps a default scoped to its utun even
		// without an exit node), nor multicast or broadcast.
		if r.Reject || r.Scoped || (r.Table != "" && r.Table != LinuxTable) {
			continue
		}
		if r.Table == "" && r.Iface != st.Iface {
			continue
		}
		p, err := netip.ParsePrefix(r.DstCIDR)
		if err != nil || r.Iface == "" {
			continue // a throw or unreachable entry
		}
		if p.Addr().IsMulticast() || p.Addr() == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			continue
		}
		switch p.Masked().String() {
		case "0.0.0.0/0", "::/0":
			st.ExitNode = true
			continue
		case "0.0.0.0/1", "128.0.0.0/1":
			halves++
			continue
		}
		if sure && !containedIn(p.Masked(), nets) && !containedIn(p.Masked(), extra) {
			extra = append(extra, p.Masked())
		}
	}
	st.ExitNode = st.ExitNode || halves == 2
	slices.SortStableFunc(extra, func(a, b netip.Prefix) int { return a.Bits() - b.Bits() })
	nets = append(nets, extra[:min(len(extra), maxNetworks)]...)
	for _, n := range nets {
		st.Networks = append(st.Networks, n.String())
	}
	return st, true
}

// Networks parses a status's networks.
func Networks(st domain.TailscaleStatus) []netip.Prefix {
	var out []netip.Prefix
	for _, n := range st.Networks {
		if p, err := netip.ParsePrefix(n); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func containedIn(p netip.Prefix, nets []netip.Prefix) bool {
	return slices.ContainsFunc(nets, func(n netip.Prefix) bool {
		return n.Addr().Is4() == p.Addr().Is4() && n.Bits() <= p.Bits() && n.Contains(p.Addr())
	})
}
