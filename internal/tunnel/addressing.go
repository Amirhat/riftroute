package tunnel

import (
	"fmt"
	"net/netip"

	"github.com/Amirhat/riftroute/internal/domain"
)

// A tunnel's server chooses the tunnel's own addressing (ifconfig,
// ifconfig-ipv6, topology), and route-nopull doesn't stop that: the kernel
// routes the tunnel's network — and a point-to-point peer — into it, whatever
// routes the user listed. vetAddressing refuses addressing that would pull in
// traffic the tunnel has no business carrying.

// privateV4 is address space a tunnel's network normally comes from.
var privateV4 = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT, common for VPNs
}

// How wide a tunnel's own network may be: /16 in private IPv4 space; in
// public IPv4 space only the tunnel's own address (/32) — a public network or
// peer would pull traffic to hosts the server chose into it; IPv6 /48 in ULA
// space, a /64 in global space (IPv6 is only pulled when the user routes it).
const (
	minPrivateV4, minPublicV4 = 16, 32
	minULAV6, minGlobalV6     = 48, 64
)

// addressingEnv is what the tunnel's addressing is checked against.
type addressingEnv struct {
	iface     string         // the tunnel's interface
	ifaces    []domain.Iface // every interface, the tunnel's included
	protected []netip.Addr   // gateways, resolvers, watchdog anchors
	servers   []netip.Addr   // the tunnel's own server addresses
	ours      []netip.Prefix // the routes RiftRoute puts into the tunnel for the user
	// configured: the addresses come from the tunnel's own configuration
	// (WireGuard's Address), not from its server.
	configured bool
}

// vetAddressing checks the tunnel's networks and the routes the kernel put
// into its interface that RiftRoute didn't. It returns why it refuses, or "".
func vetAddressing(nets []netip.Prefix, routes []domain.Route, env addressingEnv) string {
	var own []netip.Prefix
	for _, n := range nets {
		n = n.Masked()
		if n.Addr().Is6() && n.Addr().IsLinkLocalUnicast() {
			continue // every interface's fe80::/64
		}
		if why := vetNetwork(n, env); why != "" {
			if env.configured {
				return fmt.Sprintf("the configuration's Address %s %s; refusing", n.Addr(), why)
			}
			return fmt.Sprintf("the server gave the tunnel the network %s, which %s; refusing", n, why)
		}
		own = append(own, n)
	}
	for _, r := range routes {
		if r.Iface != env.iface || r.Owner == domain.OwnerRiftRoute {
			continue
		}
		dst, err := netip.ParsePrefix(r.DstCIDR)
		if err != nil {
			continue // a zoned (fe80::%utun…) or odd entry: not addressable from here
		}
		dst = dst.Masked()
		if plumbing(dst) || insideAny(dst, own) {
			continue
		}
		// Inside the user's own routes it isn't stray — but the server may
		// still have chosen it (a p2p peer): it must not hold a resolver, an
		// anchor or the tunnel's own server, which the planner keeps out of
		// the tunnel even where the user's route covers them.
		if insideAny(dst, env.ours) {
			if why := holdsProtected(dst, env); why != "" {
				return fmt.Sprintf("the server's settings put a route to %s into the tunnel, which %s; refusing", dst, why)
			}
			continue
		}
		// net30/p2p: a host route to the peer beside a local address — in
		// private space only (a public peer is a host the server chose).
		if peer30(dst, nets) {
			why := vetNetwork(dst, env)
			if why == "" && !insideAny(dst, privateV4) {
				why = "is a public address"
			}
			if why != "" {
				return fmt.Sprintf("the server made %s the tunnel's point-to-point peer, which %s; refusing", dst.Addr(), why)
			}
			continue
		}
		return fmt.Sprintf("the server's settings put a route to %s into the tunnel, outside its own network; refusing", dst)
	}
	return ""
}

// vetNetwork says why a network (or a /32 peer) can't be the tunnel's, or "".
func vetNetwork(n netip.Prefix, env addressingEnv) string {
	a := n.Addr()
	switch {
	case a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast():
		return "isn't a usable tunnel address"
	case a.Is4() && insideAny(n, privateV4) && n.Bits() < minPrivateV4,
		a.Is4() && !insideAny(n, privateV4) && n.Bits() < minPublicV4,
		a.Is6() && isULA(a) && n.Bits() < minULAV6,
		a.Is6() && !isULA(a) && n.Bits() < minGlobalV6:
		return "is wider than a tunnel's own network may be"
	}
	if why := holdsProtected(n, env); why != "" {
		return why
	}
	for _, ifc := range env.ifaces {
		if ifc.Name == env.iface {
			continue
		}
		for _, s := range ifc.Addrs {
			o, err := netip.ParsePrefix(s)
			if err != nil || o.Addr().IsLoopback() || o.Addr().IsLinkLocalUnicast() {
				continue
			}
			if o = o.Masked(); o.Overlaps(n) {
				return fmt.Sprintf("overlaps %s on %s", o, ifc.Name)
			}
		}
	}
	return ""
}

// holdsProtected says which protected address or own server n holds, or "".
func holdsProtected(n netip.Prefix, env addressingEnv) string {
	for _, p := range env.protected {
		if n.Contains(p.Unmap()) {
			return fmt.Sprintf("holds %s (your router, DNS server or connectivity check)", p)
		}
	}
	for _, s := range env.servers {
		if n.Contains(s.Unmap()) {
			return fmt.Sprintf("holds the tunnel's own server %s", s)
		}
	}
	return ""
}

// plumbing is what an OS routes into any interface on its own: multicast,
// the IPv4 limited broadcast, IPv6 link-local.
func plumbing(p netip.Prefix) bool {
	a := p.Addr()
	return a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || (a.Is6() && a.IsLinkLocalUnicast())
}

// peer30 reports a /32 beside a local IPv4 address, in the same /30: the
// peer of openvpn's net30 (or p2p) addressing.
func peer30(dst netip.Prefix, nets []netip.Prefix) bool {
	if !dst.Addr().Is4() || dst.Bits() != 32 {
		return false
	}
	for _, n := range nets {
		if n.Addr().Is4() {
			if p, _ := n.Addr().Prefix(30); p.Contains(dst.Addr()) {
				return true
			}
		}
	}
	return false
}

func insideAny(n netip.Prefix, in []netip.Prefix) bool {
	for _, o := range in {
		if o.Bits() <= n.Bits() && o.Contains(n.Addr()) {
			return true
		}
	}
	return false
}

func isULA(a netip.Addr) bool { return a.Is6() && a.As16()[0]&0xfe == 0xfc }
