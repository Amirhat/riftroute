package tailscale

import (
	"slices"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

func TestDetect(t *testing.T) {
	en0 := domain.Iface{Name: "en0", Up: true, Addrs: []string{"192.168.1.7/24"}}
	if _, ok := Detect([]domain.Iface{en0}, nil); ok {
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
	st, ok := Detect([]domain.Iface{en0, ts0}, linux)
	if !ok || st.Iface != "tailscale0" || st.ExitNode || !slices.Equal(st.Networks, []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48", "10.20.0.0/16"}) {
		t.Fatalf("linux: %+v %v", st, ok)
	}
	st, _ = Detect([]domain.Iface{en0, ts0}, append(linux, domain.Route{DstCIDR: "0.0.0.0/0", Iface: "tailscale0", Table: "52"}))
	if !st.ExitNode {
		t.Fatal("linux exit node not seen")
	}

	// macOS: a utun holding its address, its routes in main; an exit node
	// as two halves.
	utun := domain.Iface{Name: "utun5", Up: true, Addrs: []string{"100.101.2.3/32"}}
	other := domain.Iface{Name: "utun3", Up: true, Addrs: []string{"10.8.0.2/32"}}
	mac := []domain.Route{
		{DstCIDR: "100.64.0.0/10", Iface: "utun5"},
		{DstCIDR: "172.16.9.0/24", Iface: "utun5"},
		{DstCIDR: "0.0.0.0/1", Iface: "utun5"},
		{DstCIDR: "128.0.0.0/1", Iface: "utun5"},
		{DstCIDR: "10.8.0.0/24", Iface: "utun3"},
	}
	st, ok = Detect([]domain.Iface{en0, other, utun}, mac)
	if !ok || st.Iface != "utun5" || !st.ExitNode || !slices.Contains(st.Networks, "172.16.9.0/24") || slices.Contains(st.Networks, "10.8.0.0/24") {
		t.Fatalf("macOS: %+v %v", st, ok)
	}
	// Down: not there.
	utun.Up = false
	if _, ok := Detect([]domain.Iface{en0, utun}, mac); ok {
		t.Fatal("a down interface counted")
	}
}
