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

// Detect finds Tailscale among ifaces — tailscale0 (Linux), or an interface
// holding an address in its ranges (a utun on macOS) — and, from routes (the
// main table's, and on Linux table 52's), what it routes and whether its
// exit node is on (a default route into it). ok is false without one.
func Detect(ifaces []domain.Iface, routes []domain.Route) (st domain.TailscaleStatus, ok bool) {
	for _, i := range ifaces {
		if i.Up && isTailscale(i) {
			st.Iface, ok = i.Name, true
			break
		}
	}
	if !ok {
		return st, false
	}
	nets := []netip.Prefix{CGNAT, ULA}
	halves := 0
	for _, r := range routes {
		if r.Reject || (r.Table != "" && r.Table != LinuxTable) {
			continue
		}
		if r.Table == "" && r.Iface != st.Iface {
			continue
		}
		p, err := netip.ParsePrefix(r.DstCIDR)
		if err != nil || r.Iface == "" {
			continue // a throw or unreachable entry
		}
		switch p.Masked().String() {
		case "0.0.0.0/0", "::/0":
			st.ExitNode = true
			continue
		case "0.0.0.0/1", "128.0.0.0/1":
			halves++
			continue
		}
		if !containedIn(p.Masked(), nets) {
			nets = append(nets, p.Masked())
		}
	}
	st.ExitNode = st.ExitNode || halves == 2
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

func isTailscale(i domain.Iface) bool {
	if strings.HasPrefix(i.Name, "tailscale") {
		return true
	}
	for _, a := range i.Addrs {
		if p, err := netip.ParsePrefix(a); err == nil && (CGNAT.Contains(p.Addr()) || ULA.Contains(p.Addr())) && strings.HasPrefix(i.Name, "utun") {
			return true
		}
	}
	return false
}

func containedIn(p netip.Prefix, nets []netip.Prefix) bool {
	return slices.ContainsFunc(nets, func(n netip.Prefix) bool {
		return n.Addr().Is4() == p.Addr().Is4() && n.Bits() <= p.Bits() && n.Contains(p.Addr())
	})
}
