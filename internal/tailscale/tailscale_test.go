package tailscale

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

func TestDetect(t *testing.T) {
	en0 := domain.Iface{Name: "en0", Up: true, Addrs: []string{"192.168.1.7/24"}}
	if _, ok := Detect([]domain.Iface{en0}, nil, nil); ok {
		t.Fatal("found Tailscale on a machine without it")
	}

	// Linux: tailscale0, its routes in table 52 (peers, a subnet, MagicDNS,
	// throw entries), an exit node.
	ts0 := domain.Iface{Name: "tailscale0", Up: true, Addrs: []string{"100.101.2.3/32", "fd7a:115c:a1e0::1/128"}}
	linux := []domain.Route{
		{DstCIDR: "100.100.100.100/32", Iface: "tailscale0", Table: "52"},
		{DstCIDR: "100.88.0.4/32", Iface: "tailscale0", Table: "52"},
		{DstCIDR: "10.20.0.0/16", Iface: "tailscale0", Table: "52"},
		{DstCIDR: "127.0.0.0/8", Table: "52"}, // throw
		{DstCIDR: "192.168.1.0/24", Iface: "en0"},
		{DstCIDR: "10.30.0.0/16", Iface: "wg0"},
	}
	st, ok := Detect([]domain.Iface{en0, ts0}, linux, nil)
	if !ok || st.Iface != "tailscale0" || st.ExitNode || !slices.Equal(st.Networks, []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48", "10.20.0.0/16"}) {
		t.Fatalf("linux: %+v %v", st, ok)
	}
	st, _ = Detect([]domain.Iface{en0, ts0}, append(linux, domain.Route{DstCIDR: "0.0.0.0/0", Iface: "tailscale0", Table: "52"}), nil)
	if !st.ExitNode {
		t.Fatal("linux exit node not seen")
	}

	// macOS: a utun holding its addresses (its IPv6 one makes it sure), its
	// routes in main; an exit node as two halves.
	utun := domain.Iface{Name: "utun5", Up: true, Addrs: []string{"100.101.2.3/32", "fd7a:115c:a1e0::5/128"}}
	other := domain.Iface{Name: "utun3", Up: true, Addrs: []string{"10.8.0.2/32"}}
	mac := []domain.Route{
		{DstCIDR: "100.64.0.0/10", Iface: "utun5"},
		{DstCIDR: "172.16.9.0/24", Iface: "utun5"},
		{DstCIDR: "0.0.0.0/1", Iface: "utun5"},
		{DstCIDR: "128.0.0.0/1", Iface: "utun5"},
		{DstCIDR: "10.8.0.0/24", Iface: "utun3"},
	}
	st, ok = Detect([]domain.Iface{en0, other, utun}, mac, nil)
	if !ok || st.Iface != "utun5" || !st.ExitNode || !slices.Contains(st.Networks, "172.16.9.0/24") || slices.Contains(st.Networks, "10.8.0.0/24") {
		t.Fatalf("macOS: %+v %v", st, ok)
	}
	// Down: not there.
	utun.Up = false
	if _, ok := Detect([]domain.Iface{en0, utun}, mac, nil); ok {
		t.Fatal("a down interface counted")
	}
}

// A CGNAT address alone isn't Tailscale's: Cloudflare WARP, NetBird and
// others use that space too. Without its IPv6 address, only MagicDNS among
// the resolvers makes a utun Tailscale's — and then only its own ranges are
// its networks, never the routes into it (the review's MEDIUM).
func TestACGNATVPNIsntTailscale(t *testing.T) {
	warp := domain.Iface{Name: "utun4", Up: true, Addrs: []string{"100.96.0.5/32"}, IsVPN: true}
	routes := []domain.Route{{DstCIDR: "0.0.0.0/5", Iface: "utun4"}, {DstCIDR: "8.0.0.0/7", Iface: "utun4"}, {DstCIDR: "16.0.0.0/4", Iface: "utun4"}}
	if _, ok := Detect([]domain.Iface{warp}, routes, []netip.Addr{netip.MustParseAddr("1.1.1.1")}); ok {
		t.Fatal("a CGNAT VPN taken for Tailscale")
	}
	st, ok := Detect([]domain.Iface{warp}, routes, []netip.Addr{MagicDNS})
	if !ok || !slices.Equal(st.Networks, []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"}) {
		t.Fatalf("with MagicDNS, unsure: %+v %v", st, ok)
	}
}

// A tailnet's many routes count up to maxNetworks, the widest first.
func TestDetectBoundsTheNetworks(t *testing.T) {
	ts0 := domain.Iface{Name: "tailscale0", Up: true, Addrs: []string{"100.101.2.3/32"}}
	routes := []domain.Route{{DstCIDR: "10.0.0.0/16", Iface: "tailscale0", Table: "52"}}
	for i := range 1000 {
		routes = append(routes, domain.Route{DstCIDR: netip.AddrFrom4([4]byte{172, 16, byte(i >> 8), byte(i)}).String() + "/32", Iface: "tailscale0", Table: "52"})
	}
	st, _ := Detect([]domain.Iface{ts0}, routes, nil)
	if len(st.Networks) != 2+maxNetworks || st.Networks[2] != "10.0.0.0/16" {
		t.Fatalf("%d networks, third %s", len(st.Networks), st.Networks[2])
	}
}

// The routes macOS's Tailscale app really leaves (no exit node): a default
// scoped to its utun, its peers' /32s, MagicDNS, multicast and broadcast —
// beside the main VPN's default. No exit node, and only its peers are its.
func TestDetectMacOSAsItReallyIs(t *testing.T) {
	utun8 := domain.Iface{Name: "utun8", Up: true, Addrs: []string{"100.92.45.62/32", "fd7a:115c:a1e0::b538:2d3f/48"}}
	utun4 := domain.Iface{Name: "utun4", Up: true, Addrs: []string{"10.184.16.2/32"}, IsVPN: true}
	routes := []domain.Route{
		{DstCIDR: "0.0.0.0/0", Iface: "utun4"},
		{DstCIDR: "0.0.0.0/0", Gateway: "192.168.88.1", Iface: "en0", Scoped: true},
		{DstCIDR: "0.0.0.0/0", Iface: "utun8", Scoped: true},
		{DstCIDR: "100.66.252.1/32", Iface: "utun8"},
		{DstCIDR: "100.100.100.100/32", Iface: "utun8"},
		{DstCIDR: "224.0.0.0/4", Iface: "utun8", Scoped: true},
		{DstCIDR: "255.255.255.255/32", Iface: "utun8", Scoped: true},
	}
	st, ok := Detect([]domain.Iface{utun4, utun8}, routes, []netip.Addr{MagicDNS})
	if !ok || st.Iface != "utun8" || st.ExitNode || !slices.Equal(st.Networks, []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"}) {
		t.Fatalf("%+v %v", st, ok)
	}
}

// Two utuns with a CGNAT address and MagicDNS in use (WARP beside a
// Tailscale without its IPv6 address): Tailscale's is the one MagicDNS is
// routed into — by the most specific route, as the kernel picks (WARP's
// /12 holds it too) — whichever comes first.
func TestFindPrefersTheUtunMagicDNSGoesInto(t *testing.T) {
	ifaces := []domain.Iface{
		{Name: "utun3", Up: true, Addrs: []string{"100.92.45.62/32"}},
		{Name: "utun4", Up: true, Addrs: []string{"100.96.0.5/32"}},
	}
	dns := []netip.Addr{MagicDNS}
	routes := []domain.Route{{DstCIDR: "100.100.100.100/32", Iface: "utun3"}, {DstCIDR: "100.96.0.0/12", Iface: "utun4"}}
	if name, sure, ok := Find(ifaces, routes, dns); !ok || sure || name != "utun3" {
		t.Fatalf("got %s sure=%v ok=%v", name, sure, ok)
	}
	ifaces[0], ifaces[1] = ifaces[1], ifaces[0] // WARP's first
	if name, _, _ := Find(ifaces, routes, dns); name != "utun3" {
		t.Fatalf("WARP's listed first: got %s", name)
	}
	ifaces[0], ifaces[1] = ifaces[1], ifaces[0]
	if name, _, _ := Find(ifaces, nil, dns); name != "utun3" {
		t.Fatalf("without routes: %s, want the first", name)
	}
}
