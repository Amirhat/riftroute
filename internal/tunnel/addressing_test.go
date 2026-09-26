package tunnel

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

func pfxs(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func onTun(dsts ...string) []domain.Route {
	var out []domain.Route
	for _, d := range dsts {
		out = append(out, domain.Route{DstCIDR: d, Iface: "utun9", Owner: domain.OwnerSystem})
	}
	return out
}

// The addressing a hostile server could choose to pull traffic into the
// tunnel is refused; ordinary VPN addressing isn't.
func TestVetAddressing(t *testing.T) {
	env := addressingEnv{
		iface: "utun9",
		ifaces: []domain.Iface{
			{Name: "en0", Addrs: []string{"192.168.1.23/24", "fe80::1/64"}},
			{Name: "utun4", Addrs: []string{"10.2.0.2/32"}}, // the main VPN
			{Name: "utun9", Addrs: []string{"10.99.0.2/24"}},
		},
		protected: []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("10.255.255.1"), netip.MustParseAddr("1.1.1.1")},
		servers:   []netip.Addr{netip.MustParseAddr("198.51.100.7")},
	}
	for _, tc := range []struct {
		name   string
		nets   []netip.Prefix
		routes []domain.Route
		refuse string // substring of the reason; "" = accepted
	}{
		{"subnet", pfxs("10.99.0.2/24"), onTun("10.99.0.0/24"), ""},
		{"net30", pfxs("10.8.0.6/32"), onTun("10.8.0.5/32"), ""},
		{"CGNAT", pfxs("100.64.3.2/16"), nil, ""},
		{"ULA v6", pfxs("fd00:1::2/64"), onTun("fd00:1::/64", "fe80::/64"), ""},
		{"global v6 /64", pfxs("2001:db8:1::2/64"), nil, ""},
		{"multicast plumbing", pfxs("10.99.0.2/24"), onTun("224.0.0.0/4", "255.255.255.255/32"), ""},
		{"public own address only", pfxs("203.0.113.9/32"), nil, ""},

		{"private /8", pfxs("10.1.2.3/8"), nil, "wider"},
		{"public /24", pfxs("8.8.8.9/24"), nil, "wider"},
		{"public net30 peer", pfxs("8.8.8.9/32"), onTun("8.8.8.8/32"), "public address"},
		{"anchor as peer", pfxs("1.1.1.2/32"), onTun("1.1.1.1/32"), "1.1.1.1"},
		{"router as peer", pfxs("192.168.1.2/32"), onTun("192.168.1.1/32"), "192.168.1."},
		{"overlaps the LAN", pfxs("192.168.1.130/25"), nil, "en0"},
		{"holds the DNS server", pfxs("10.255.0.2/16"), nil, "10.255.255.1"},
		{"overlaps the main VPN", pfxs("10.2.0.9/16"), nil, "utun4"},
		{"holds its own server", pfxs("198.51.100.8/32"), onTun("198.51.100.7/32"), "198.51.100.7"},
		{"stray route", pfxs("10.99.0.2/24"), onTun("8.8.8.8/32"), "8.8.8.8"},
		{"metadata address", pfxs("10.99.0.2/24"), onTun("169.254.169.254/32"), "169.254.169.254"},
		{"v6 wider than ULA /48", pfxs("fd00::2/16"), nil, "wider"},
		{"global v6 wider than /64", pfxs("2000::2/3"), nil, "wider"},
		{"loopback", pfxs("127.0.0.2/30"), nil, "usable"},
	} {
		got := vetAddressing(tc.nets, tc.routes, env)
		switch {
		case tc.refuse == "" && got != "":
			t.Errorf("%s: refused: %s", tc.name, got)
		case tc.refuse != "" && !strings.Contains(got, tc.refuse):
			t.Errorf("%s: got %q, want a refusal mentioning %q", tc.name, got, tc.refuse)
		}
	}
}
