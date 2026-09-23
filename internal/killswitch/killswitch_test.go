package killswitch

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

var sample = Config{
	PhysIfaces: []string{"en0", "en4"},
	Gateway:    "192.168.50.254",
	LANSubnets: []string{"192.168.50.0/24", "2a01:4f8:1:2::/64"},
	Bypass:     []string{"185.10.75.0/24", "2a02:ec0::/32"},
}

func mustContain(t *testing.T, s string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(s, w) {
			t.Errorf("missing %q in:\n%s", w, s)
		}
	}
}

// The heart of the fix: block rules only — user-owned sockets leaving a
// physical interface for anywhere outside the allow table. Root (VPN
// helpers) is never blocked, tunnels are never guarded whatever their name,
// and the anchor PASSES nothing, so it can't reopen another firewall's block
// or change its state handling. VPN ports are carved out of the block.
func TestPfRulesetIsBlockOnly(t *testing.T) {
	s := PfRuleset(sample)
	mustContain(t, s,
		"table <rr_ks_allow> persist { 192.168.50.254 192.168.50.0/24 2a01:4f8:1:2::/64 185.10.75.0/24 2a02:ec0::/32 169.254.0.0/16 224.0.0.0/4 255.255.255.255 fe80::/10 ff00::/8 }",
		"block return out on { en0 en4 } proto udp to ! <rr_ks_allow> port { 0:499 501:1193 1195:4499 4501:51819 51821:65535 } user { 499 >< 65534 > 65534 }",
		"block return out on { en0 en4 } proto tcp to ! <rr_ks_allow> port { 0:1193 1195:65535 } user { 499 >< 65534 > 65534 }",
	)
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "pass") {
			t.Errorf("the anchor must pass nothing (it would override other firewalls): %q", line)
		}
	}
	for _, bad := range []string{"quick", "block out all", "block drop out all", "utun", "ipsec", "60001"} {
		if strings.Contains(s, bad) {
			t.Errorf("ruleset must not contain %q:\n%s", bad, s)
		}
	}
}

func TestPortsExcept(t *testing.T) {
	if got := portsExcept([]int{1194, 500, 51820, 4500}); got != "0:499 501:1193 1195:4499 4501:51819 51821:65535" {
		t.Fatalf("udp = %q", got)
	}
	if got := portsExcept([]int{0, 65535}); got != "1:65534" {
		t.Fatalf("edges = %q", got)
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
	for name, cfg := range map[string]Config{"full": sample, "minimal": {PhysIfaces: []string{"en0"}}} {
		cmd := exec.Command("pfctl", "-n", "-f", "-")
		cmd.Stdin = bytes.NewReader([]byte(PfRuleset(cfg)))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: pfctl rejected the ruleset: %v\n%s\n--- ruleset ---\n%s", name, err, out, PfRuleset(cfg))
		}
	}
}

func TestNftRulesetGuardsOnlyPhysicalUserTraffic(t *testing.T) {
	s := NftRuleset(sample)
	mustContain(t, s,
		"add table inet riftroute_ks\ndelete table inet riftroute_ks\n", // atomic re-create: no stale set elements
		"policy accept;",
		`oifname != { "en0", "en4" } accept`, // tunnels, whatever their name, are never guarded
		"flags interval", "auto-merge",
		"elements = { 192.168.50.254, 192.168.50.0/24, 185.10.75.0/24, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 }",
		"elements = { 2a01:4f8:1:2::/64, 2a02:ec0::/32, fe80::/10, ff00::/8 }",
		"ip daddr @allow4 accept", "ip6 daddr @allow6 accept",
		"udp dport { 500, 4500, 51820, 1194 } accept",
		"rt ipsec exists accept", // policy-based IPsec (strongSwan/libreswan) has no tunnel interface
		"meta skuid { 1000-61183, 65520-65533, 65535-4294967294 } meta l4proto { tcp, udp } reject",
	)
	for _, bad := range []string{"policy drop", "ct state established", "oifname \"wg*\""} {
		if strings.Contains(s, bad) {
			t.Errorf("ruleset must not contain %q", bad)
		}
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
		{Name: "usb0", Up: true, Kind: domain.IfaceKindOther, Addrs: []string{"172.20.10.2/28"}}, // tethered uplink
		{Name: "nordlynx", Up: true, Kind: domain.IfaceKindOther},                                // a VPN with an odd name
		{Name: "utun4", Up: true, IsVPN: true, Addrs: []string{"10.8.0.2/32"}},
	}
	owned := []domain.ManagedRoute{
		{Route: domain.Route{DstCIDR: "185.10.75.0/24", Iface: "en0"}},            // exclude: goes direct → allowed
		{Route: domain.Route{DstCIDR: "185.10.75.0/24", Iface: "en0"}},            // duplicate
		{Route: domain.Route{DstCIDR: "10.200.0.0/16", Iface: "utun4"}},           // via a tunnel: not guarded anyway
		{Route: domain.Route{DstCIDR: "0.0.0.0/0", Iface: "wg0", Table: "5252"}},  // include-mode default, tunnel gone
		{Route: domain.Route{DstCIDR: "0.0.0.0/0", Iface: "en0"}},                 // never "allow everything"
		{Route: domain.Route{DstCIDR: "8.8.8.0/24", Iface: "en0", Table: "5252"}}, // policy table, not main
	}
	// utun0 holds the IPv6 default on a VPN'd Mac: an uplink, but a tunnel —
	// it must never be guarded (that would lock the VPN's own traffic out).
	got := Derive(ifaces, netip.MustParseAddr("172.20.10.1"), []string{"usb0", "utun4"}, owned)
	want := Config{
		PhysIfaces: []string{"en0", "usb0"}, // physical + the uplink; never tunnels or unknown VPNs
		Gateway:    "172.20.10.1",
		LANSubnets: []string{"172.20.10.0/28", "192.168.50.0/24", "2a01:4f8:1:2::/64"},
		Bypass:     []string{"185.10.75.0/24"},
	}
	if !got.Equal(want) {
		t.Fatalf("Derive =\n%+v\nwant\n%+v", got, want)
	}
}

// Regression (review finding): Linux include mode keeps its 0.0.0.0/0-via-wg0
// route in the store after wg0 vanishes; it must never turn into "allow
// everything" — which is exactly when the kill switch has to hold.
func TestDeriveNeverAllowsEverythingWhenTheTunnelVanishes(t *testing.T) {
	ifaces := []domain.Iface{{Name: "eth0", Up: true, Kind: domain.IfaceKindPhysical, Addrs: []string{"192.168.1.5/24"}}}
	owned := []domain.ManagedRoute{
		{Route: domain.Route{DstCIDR: "0.0.0.0/0", Iface: "wg0", Table: "5252"}},
		{Route: domain.Route{DstCIDR: "::/0", Iface: "wg0", Table: "5252"}},
	}
	cfg := Derive(ifaces, netip.MustParseAddr("192.168.1.1"), []string{"eth0"}, owned)
	if len(cfg.Bypass) != 0 {
		t.Fatalf("a vanished tunnel's routes leaked into the allow list: %v", cfg.Bypass)
	}
	for _, r := range []string{NftRuleset(cfg), PfRuleset(cfg)} {
		if strings.Contains(r, "0.0.0.0/0") || strings.Contains(r, "::/0") {
			t.Fatalf("rules allow everything:\n%s", r)
		}
	}
}

func TestConfigEqualIgnoresOrder(t *testing.T) {
	a := Config{PhysIfaces: []string{"en4", "en0"}, Bypass: []string{"b", "a"}}
	b := Config{PhysIfaces: []string{"en0", "en4"}, Bypass: []string{"a", "b"}}
	if !a.Equal(b) {
		t.Fatal("same sets in different order must be equal")
	}
	b.Bypass = []string{"a", "c"}
	if a.Equal(b) {
		t.Fatal("a changed bypass set must count as a change")
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

func TestEnableRefusesNothingToGuard(t *testing.T) {
	if err := (&Fake{}).Enable(context.Background(), Config{}); !errors.Is(err, ErrNoInterface) {
		t.Fatalf("err = %v, want ErrNoInterface", err)
	}
	if err := (&realManager{backend: "pf"}).Enable(context.Background(), Config{}); !errors.Is(err, ErrNoInterface) {
		t.Fatalf("real manager must refuse before touching pf: %v", err)
	}
}

// Modems whose names aren't "physical" (raw-IP LTE, USB tethering) are
// guarded even when they don't hold the default route.
func TestDeriveGuardsModems(t *testing.T) {
	ifaces := []domain.Iface{
		{Name: "eth0", Up: true, Kind: domain.IfaceKindPhysical},
		{Name: "wwan0", Up: true, Kind: domain.IfaceKindOther},
		{Name: "usb0", Up: true, Kind: domain.IfaceKindOther},
		{Name: "tailscale0", Up: true, Kind: domain.IfaceKindOther},
	}
	got := Derive(ifaces, netip.Addr{}, nil, nil).PhysIfaces
	if !slices.Equal(got, []string{"eth0", "usb0", "wwan0"}) {
		t.Fatalf("guarded %v", got)
	}
}
