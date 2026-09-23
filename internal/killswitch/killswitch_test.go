package killswitch

import (
	"bytes"
	"context"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

var sample = Config{
	TunnelIfaces: []string{"ipsec0", "utun4"},
	Gateway:      "192.168.50.254",
	LANSubnets:   []string{"192.168.50.0/24", "2a01:4f8:1:2::/64"},
	Bypass:       []string{"185.10.75.0/24", "2a02:ec0::/32"},
}

func mustContain(t *testing.T, s string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(s, w) {
			t.Errorf("missing %q in:\n%s", w, s)
		}
	}
}

// The heart of the fix: only USER-owned sockets are blocked, so a VPN
// client's privileged helper (root) can always reach its server — the old
// allow-list (tunnel+gateway+LAN, then `block out all`) blocked the VPN's
// own handshake and it could never reconnect.
func TestPfRulesetBlocksOnlyUserSockets(t *testing.T) {
	s := PfRuleset(sample)
	mustContain(t, s,
		"block return out proto { tcp udp } all user 499 >< 60001",
		"pass out on lo0 all",
		"pass out on { ipsec0 utun4 } all",
		"table <rr_ks_allow> persist { 192.168.50.254 192.168.50.0/24 2a01:4f8:1:2::/64 185.10.75.0/24 2a02:ec0::/32 }",
		"pass out to <rr_ks_allow>",
		"pass out to { 224.0.0.0/4 255.255.255.255 fe80::/10 ff00::/8 }",
		"pass out proto udp to port { 500 4500 51820 1194 }",
		"pass out proto tcp to port { 1194 }",
	)
	if strings.Contains(s, "block out all") || strings.Contains(s, "block drop out all") {
		t.Error("must never block everyone: root VPN helpers need to reconnect")
	}
	// Non-quick: a quick pass elsewhere (include-mode route-to, a VPN client's
	// own firewall) must still win.
	if strings.Contains(s, "quick") {
		t.Errorf("rules must not be quick:\n%s", s)
	}
	// pf is last-match-wins: the block must come BEFORE the allowances.
	if strings.Index(s, "block return") > strings.Index(s, "pass out on lo0") {
		t.Error("block must precede the pass rules")
	}
}

func TestPfRulesetWithNothingToAllow(t *testing.T) {
	s := PfRuleset(Config{})
	if strings.Contains(s, "<rr_ks_allow>") || strings.Contains(s, "pass out on { ") {
		t.Errorf("empty table/interface lists would not parse:\n%s", s)
	}
}

// Syntax-check the rendered anchor against the REAL pfctl in parse-only mode
// (-n): nothing is loaded, the kernel isn't touched, no root needed.
func TestPfRulesetParsesWithRealPfctl(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("pfctl is macOS-only here")
	}
	if _, err := exec.LookPath("pfctl"); err != nil {
		t.Skip("pfctl not found")
	}
	for name, cfg := range map[string]Config{"full": sample, "empty": {}} {
		cmd := exec.Command("pfctl", "-n", "-f", "-")
		cmd.Stdin = bytes.NewReader([]byte(PfRuleset(cfg)))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: pfctl rejected the ruleset: %v\n%s\n--- ruleset ---\n%s", name, err, out, PfRuleset(cfg))
		}
	}
}

func TestNftRulesetBlocksOnlyUserSockets(t *testing.T) {
	s := NftRuleset(sample)
	mustContain(t, s,
		"add table inet riftroute_ks\ndelete table inet riftroute_ks\n", // atomic re-create: no stale set elements
		"policy accept;",
		`oif "lo" accept`,
		`oifname "ipsec0" accept`, `oifname "utun4" accept`,
		`oifname "wg*" accept`, `oifname "tun*" accept`, // a VPN back on a new interface is never fenced
		"flags interval", "auto-merge", // gateway inside a LAN subnet must not conflict
		"elements = { 192.168.50.254, 192.168.50.0/24, 185.10.75.0/24, 224.0.0.0/4, 255.255.255.255 }",
		"elements = { 2a01:4f8:1:2::/64, 2a02:ec0::/32, fe80::/10, ff00::/8 }",
		"ip daddr @allow4 accept", "ip6 daddr @allow6 accept",
		"udp dport { 500, 4500, 51820, 1194 } accept",
		"meta skuid 1000-60000 meta l4proto { tcp, udp } reject",
	)
	if strings.Contains(s, "policy drop") {
		t.Error("must not drop everyone: root VPN helpers and kernel WireGuard need to reconnect")
	}
	if strings.Contains(s, "ct state established") {
		t.Error("an established user flow re-routed outside the tunnel is still a leak")
	}
	if strings.Index(s, "reject") < strings.Index(s, "ip daddr @allow4") {
		t.Error("the user reject must come after the allowances (first match wins in nft)")
	}
}

func TestDeriveFromLiveState(t *testing.T) {
	ifaces := []domain.Iface{
		{Name: "lo0", Up: true, Kind: domain.IfaceKindLoopback, Addrs: []string{"127.0.0.1/8"}},
		{Name: "en0", Up: true, Kind: domain.IfaceKindPhysical, Addrs: []string{"192.168.50.23/24", "fe80::1/64", "2a01:4f8:1:2::5/64"}},
		{Name: "en1", Up: false, Kind: domain.IfaceKindPhysical, Addrs: []string{"10.9.9.9/24"}},
		{Name: "utun4", Up: true, IsVPN: true, Addrs: []string{"10.8.0.2/32"}},
		{Name: "utun1", Up: false, IsVPN: true},
		{Name: "ipsec0", Up: true, IsVPN: true},
	}
	owned := []domain.ManagedRoute{
		{Route: domain.Route{DstCIDR: "185.10.75.0/24", Iface: "en0"}},  // exclude: goes direct → allowed
		{Route: domain.Route{DstCIDR: "185.10.75.0/24", Iface: "en0"}},  // duplicate
		{Route: domain.Route{DstCIDR: "10.200.0.0/16", Iface: "utun4"}}, // via the tunnel: already allowed
		{Route: domain.Route{DstCIDR: "not-a-cidr", Iface: "en0"}},      // ignored
	}
	got := Derive(ifaces, netip.MustParseAddr("192.168.50.254"), owned)
	want := Config{
		TunnelIfaces: []string{"ipsec0", "utun4"},
		Gateway:      "192.168.50.254",
		LANSubnets:   []string{"192.168.50.0/24", "2a01:4f8:1:2::/64"},
		Bypass:       []string{"185.10.75.0/24"},
	}
	if !got.Equal(want) {
		t.Fatalf("Derive =\n%+v\nwant\n%+v", got, want)
	}
}

func TestConfigEqualIgnoresOrder(t *testing.T) {
	a := Config{TunnelIfaces: []string{"utun4", "ipsec0"}, Bypass: []string{"b", "a"}}
	b := Config{TunnelIfaces: []string{"ipsec0", "utun4"}, Bypass: []string{"a", "b"}}
	if !a.Equal(b) {
		t.Fatal("same sets in different order must be equal")
	}
	b.TunnelIfaces = []string{"ipsec0", "utun5"}
	if a.Equal(b) {
		t.Fatal("a VPN on a new interface must count as a change")
	}
}

// Before this fix the macOS kill switch loaded an anchor pf.conf never
// referenced: it reported "on" and enforced nothing. Effective now requires
// the LOADED main ruleset to reference it and pf to be running.
func TestPfEffectivenessParsers(t *testing.T) {
	main := "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\nanchor \"riftroute\" all\n"
	if PfHooked(main) {
		t.Fatal("the routing anchor is not the kill switch anchor")
	}
	if !PfHooked(main + "anchor \"riftroute_ks\" all\n") {
		t.Fatal("hooked anchor not detected")
	}
	if !PfRunning("Status: Enabled for 0 days 00:10:02           Debug: Urgent\n") {
		t.Fatal("running pf not detected")
	}
	if PfRunning("Status: Disabled                              Debug: Urgent\n") {
		t.Fatal("disabled pf reported running")
	}
}

func TestFakeToggles(t *testing.T) {
	f := &Fake{}
	ctx := context.Background()
	if on, _ := f.Enabled(ctx); on {
		t.Fatal("should start off")
	}
	if err := f.Enable(ctx, sample); err != nil {
		t.Fatal(err)
	}
	if on, _ := f.Enabled(ctx); !on || !f.Last().Equal(sample) || f.Enables != 1 {
		t.Fatalf("after Enable: on=%v last=%+v enables=%d", on, f.Last(), f.Enables)
	}
	if err := f.Disable(ctx); err != nil {
		t.Fatal(err)
	}
	if st := f.Status(ctx); st.Loaded || st.Effective {
		t.Fatal("should be off after Disable")
	}
}
