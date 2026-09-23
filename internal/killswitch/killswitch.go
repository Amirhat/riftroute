// Package killswitch keeps the user's apps from reaching the internet outside
// the VPN tunnel — while the tunnel is down or reconnecting, their traffic is
// refused instead of silently leaking onto the physical network (spec §6/§7).
// Linux uses nftables (a dedicated inet table); macOS uses pf (a dedicated
// anchor, hooked into pf.conf so it is actually evaluated). The rule
// generators are pure and unit-tested; real application is exec-only
// (arg-array). The agent never enables it on a live host.
//
// # Why it scopes by socket owner
//
// A kill switch that lives outside the VPN client can't know which server the
// VPN will reconnect to (clients rotate servers and ports, often 443). An
// allow-list of "the tunnel, the gateway and the LAN" therefore blocks the
// VPN's own handshake — it can never reconnect. Instead, the block applies to
// TCP/UDP sockets owned by regular login accounts: the browser, messengers,
// everything a person runs. Root and system accounts are never blocked;
// that's where VPN clients' privileged helpers, macOS IKEv2/IPsec and kernel
// WireGuard live, so a VPN can always (re)connect.
//
// Trade-offs, stated in the UI too: system services (the OS resolver's DNS
// lookups, update checks) can still reach the network while the tunnel is
// down; and a VPN app that runs as the user (some App Store VPNs) can
// reconnect only on standard VPN ports (UDP 500/4500/51820/1194, TCP 1194).
package killswitch

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/pfconf"
)

// Config is what the kill switch lets user apps reach outside the tunnel.
type Config struct {
	// TunnelIfaces are the up tunnel interfaces. The daemon re-syncs this as
	// VPNs come and go — a VPN reconnecting on a new utunN must not be fenced.
	TunnelIfaces []string
	Gateway      string
	LANSubnets   []string
	// Bypass are destinations RiftRoute itself routes outside the tunnel
	// (exclude-mode profiles): the user asked for them to go direct, so they
	// are not leaks and must not be blocked.
	Bypass []string
}

// Equal reports whether two configs render the same rules (order-insensitive).
func (c Config) Equal(o Config) bool {
	return c.Gateway == o.Gateway && sameSet(c.TunnelIfaces, o.TunnelIfaces) &&
		sameSet(c.LANSubnets, o.LANSubnets) && sameSet(c.Bypass, o.Bypass)
}

func sameSet(a, b []string) bool {
	a, b = sorted(a), sorted(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sorted(v []string) []string {
	out := append([]string(nil), v...)
	sort.Strings(out)
	return out
}

// Derive computes the config from live state: up tunnels, the LAN subnets of
// up physical interfaces, the physical gateway, and the destinations of
// RiftRoute-owned routes that leave through a non-tunnel interface.
func Derive(ifaces []domain.Iface, gateway netip.Addr, owned []domain.ManagedRoute) Config {
	var cfg Config
	isVPN := map[string]bool{}
	seenLAN := map[string]bool{}
	for _, ifc := range ifaces {
		isVPN[ifc.Name] = ifc.IsVPN
		if !ifc.Up || ifc.Kind == domain.IfaceKindLoopback {
			continue
		}
		if ifc.IsVPN {
			cfg.TunnelIfaces = append(cfg.TunnelIfaces, ifc.Name)
			continue
		}
		for _, a := range ifc.Addrs {
			pfx, err := netip.ParsePrefix(a)
			if err != nil || pfx.Addr().IsLinkLocalUnicast() {
				continue // link-local is allowed wholesale below
			}
			if s := pfx.Masked().String(); !seenLAN[s] {
				seenLAN[s] = true
				cfg.LANSubnets = append(cfg.LANSubnets, s)
			}
		}
	}
	if gateway.IsValid() {
		cfg.Gateway = gateway.String()
	}
	seenBypass := map[string]bool{}
	for _, mr := range owned {
		if isVPN[mr.Iface] || mr.DstCIDR == "" || seenBypass[mr.DstCIDR] {
			continue
		}
		if _, err := netip.ParsePrefix(mr.DstCIDR); err != nil {
			continue
		}
		seenBypass[mr.DstCIDR] = true
		cfg.Bypass = append(cfg.Bypass, mr.DstCIDR)
	}
	sort.Strings(cfg.TunnelIfaces)
	sort.Strings(cfg.LANSubnets)
	sort.Strings(cfg.Bypass)
	return cfg
}

// Status is what's installed and whether the packet filter enforces it.
type Status struct {
	Loaded    bool // our rules are installed
	Effective bool // …and actually evaluated (macOS: anchor hooked + pf enabled)
}

// Manager enables/disables the kill switch and reports its state.
type Manager interface {
	Enable(ctx context.Context, cfg Config) error
	Disable(ctx context.Context) error
	// Enabled reports whether the kill switch is actually in force.
	Enabled(ctx context.Context) (bool, error)
	Status(ctx context.Context) Status
	Backend() string // "nftables" | "pf" | "fake" | "unsupported"
}

// New returns the per-OS manager.
func New() Manager {
	switch runtime.GOOS {
	case "linux":
		return &realManager{backend: "nftables"}
	case "darwin":
		return &realManager{backend: "pf"}
	default:
		return &realManager{backend: "unsupported"}
	}
}

const (
	nftTable = "riftroute_ks"
	pfAnchor = "riftroute_ks"
	enableTO = 10 * time.Second

	// Regular login accounts — whose traffic must stay in the tunnel. Below
	// are root and system accounts; above, "nobody" (65534, or -2 on macOS).
	darwinFirstUser, linuxFirstUser = 500, 1000
	lastUser                        = 60000

	pfHookBegin = "# >>> riftroute kill switch (managed — do not edit) >>>"
	pfHookEnd   = "# <<< riftroute kill switch (managed — do not edit) <<<"
)

// vpnUDPPorts / vpnTCPPorts are standard VPN handshake ports (IKE, IPsec
// NAT-T, WireGuard, OpenVPN): open to user-owned sockets too, so a VPN app
// running as the user can reconnect on them. No ordinary app uses them.
var (
	vpnUDPPorts = []int{500, 4500, 51820, 1194}
	vpnTCPPorts = []int{1194}
	// Always local, never a leak: IPv4 multicast/broadcast, IPv6 link-local
	// and multicast (neighbor discovery, mDNS, DHCPv6).
	localV4 = []string{"224.0.0.0/4", "255.255.255.255"}
	localV6 = []string{"fe80::/10", "ff00::/8"}
)

// PfRuleset renders the pf anchor. Rules are deliberately NOT `quick`: pf is
// last-match-wins, so a `quick` pass elsewhere — RiftRoute's own include-mode
// route-to, or a VPN client's firewall allowing its server — still wins, and
// the kill switch can't fight them.
func PfRuleset(cfg Config) string {
	var b strings.Builder
	b.WriteString("# RiftRoute kill switch: your apps reach the internet only through a VPN tunnel.\n")
	allow := allowList(cfg)
	if len(allow) > 0 {
		fmt.Fprintf(&b, "table <rr_ks_allow> persist { %s }\n", strings.Join(allow, " "))
	}
	fmt.Fprintf(&b, "block return out proto { tcp udp } all user %d >< %d\n", darwinFirstUser-1, lastUser+1)
	b.WriteString("pass out on lo0 all\n")
	if len(cfg.TunnelIfaces) > 0 {
		fmt.Fprintf(&b, "pass out on { %s } all\n", strings.Join(cfg.TunnelIfaces, " "))
	}
	if len(allow) > 0 {
		b.WriteString("pass out to <rr_ks_allow>\n")
	}
	fmt.Fprintf(&b, "pass out to { %s }\n", strings.Join(append(append([]string(nil), localV4...), localV6...), " "))
	fmt.Fprintf(&b, "pass out proto udp to port { %s }\n", joinInts(vpnUDPPorts, " "))
	fmt.Fprintf(&b, "pass out proto tcp to port { %s }\n", joinInts(vpnTCPPorts, " "))
	return b.String()
}

// NftRuleset renders an nftables script that atomically (re)creates the kill
// switch table — add+delete first, so re-rendering on a network change never
// merges stale set elements into the new ones.
func NftRuleset(cfg Config) string {
	var v4, v6 []string
	for _, a := range allowList(cfg) {
		if strings.Contains(a, ":") {
			v6 = append(v6, a)
		} else {
			v4 = append(v4, a)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\n", nftTable, nftTable)
	fmt.Fprintf(&b, "table inet %s {\n", nftTable)
	writeSet := func(name, typ string, elems []string) {
		fmt.Fprintf(&b, "  set %s {\n    type %s\n    flags interval\n    auto-merge\n", name, typ)
		if len(elems) > 0 {
			fmt.Fprintf(&b, "    elements = { %s }\n", strings.Join(elems, ", "))
		}
		b.WriteString("  }\n")
	}
	writeSet("allow4", "ipv4_addr", append(v4, localV4...))
	writeSet("allow6", "ipv6_addr", append(v6, localV6...))
	b.WriteString("  chain output {\n")
	b.WriteString("    type filter hook output priority 0; policy accept;\n")
	b.WriteString("    oif \"lo\" accept\n")
	for _, ifn := range cfg.TunnelIfaces {
		fmt.Fprintf(&b, "    oifname \"%s\" accept\n", ifn)
	}
	// Tunnels by name too, so a VPN coming back on a new interface is never
	// fenced in the seconds before the daemon re-syncs.
	for _, pat := range []string{"tun*", "wg*", "tap*", "ppp*", "ipsec*"} {
		fmt.Fprintf(&b, "    oifname \"%s\" accept\n", pat)
	}
	b.WriteString("    ip daddr @allow4 accept\n")
	b.WriteString("    ip6 daddr @allow6 accept\n")
	fmt.Fprintf(&b, "    udp dport { %s } accept\n", joinInts(vpnUDPPorts, ", "))
	fmt.Fprintf(&b, "    tcp dport { %s } accept\n", joinInts(vpnTCPPorts, ", "))
	fmt.Fprintf(&b, "    meta skuid %d-%d meta l4proto { tcp, udp } reject\n", linuxFirstUser, lastUser)
	b.WriteString("  }\n}\n")
	return b.String()
}

// allowList is the gateway, LAN subnets and bypass destinations, deduped.
func allowList(cfg Config) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	add(cfg.Gateway)
	for _, v := range cfg.LANSubnets {
		add(v)
	}
	for _, v := range cfg.Bypass {
		add(v)
	}
	return out
}

func joinInts(v []int, sep string) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = fmt.Sprint(n)
	}
	return strings.Join(s, sep)
}

// --- real (pf / nftables) ---

type realManager struct {
	backend string

	mu        sync.Mutex
	cached    Status
	cachedAt  time.Time
	confPath  string // pf.conf (tests override)
	tokenPath string // our `pfctl -E` reference (tests override)
}

// statusTTL bounds how often Enabled re-runs pfctl: State (and so this) is
// polled every few seconds.
const statusTTL = 3 * time.Second

func (m *realManager) Backend() string { return m.backend }

func (m *realManager) conf() string {
	if m.confPath != "" {
		return m.confPath
	}
	return pfconf.Path
}

func (m *realManager) token() string {
	if m.tokenPath != "" {
		return m.tokenPath
	}
	return "/var/run/riftroute.ks.token"
}

func (m *realManager) Enable(ctx context.Context, cfg Config) error {
	defer m.invalidate()
	switch m.backend {
	case "nftables":
		return runStdin(ctx, NftRuleset(cfg), "nft", "-f", "-")
	case "pf":
		// Hook first, then load the anchor: reloading pf.conf rebuilds the
		// main ruleset, so the anchor is (re)filled after it.
		if err := m.ensureHook(ctx); err != nil {
			return err
		}
		if err := runStdin(ctx, PfRuleset(cfg), "pfctl", "-a", pfAnchor, "-f", "-"); err != nil {
			return err
		}
		m.ensurePFEnabled(ctx)
		return nil
	default:
		return fmt.Errorf("kill switch unsupported on %s", runtime.GOOS)
	}
}

func (m *realManager) Disable(ctx context.Context) error {
	defer m.invalidate()
	switch m.backend {
	case "nftables":
		_, err := run(ctx, "nft", "delete", "table", "inet", nftTable)
		if err != nil && strings.Contains(err.Error(), "No such file") {
			return nil // already gone
		}
		return err
	case "pf":
		_, _ = run(ctx, "pfctl", "-a", pfAnchor, "-F", "all") // rules + table
		err := m.dropHook(ctx)
		m.releasePF(ctx)
		return err
	default:
		return nil
	}
}

func (m *realManager) Enabled(ctx context.Context) (bool, error) {
	return m.Status(ctx).Effective, nil
}

func (m *realManager) Status(ctx context.Context) Status {
	m.mu.Lock()
	if time.Since(m.cachedAt) < statusTTL {
		st := m.cached
		m.mu.Unlock()
		return st
	}
	m.mu.Unlock()

	var st Status
	switch m.backend {
	case "nftables":
		_, err := run(ctx, "nft", "list", "table", "inet", nftTable)
		st.Loaded = err == nil
		st.Effective = st.Loaded // a base chain with a hook is always evaluated
	case "pf":
		if out, err := run(ctx, "pfctl", "-a", pfAnchor, "-s", "rules"); err == nil {
			st.Loaded = strings.TrimSpace(out) != ""
		}
		if st.Loaded {
			main, _ := run(ctx, "pfctl", "-s", "rules")
			info, _ := run(ctx, "pfctl", "-s", "info")
			st.Effective = PfHooked(main) && PfRunning(info)
		}
	}
	m.mu.Lock()
	m.cached, m.cachedAt = st, time.Now()
	m.mu.Unlock()
	return st
}

func (m *realManager) invalidate() {
	m.mu.Lock()
	m.cachedAt = time.Time{}
	m.mu.Unlock()
}

// PfHooked reports whether the LOADED main ruleset (`pfctl -s rules`)
// references our anchor — an unreferenced anchor is never evaluated. (Until
// this fix the macOS kill switch loaded rules no one referenced: it reported
// "on" and did nothing.)
func PfHooked(mainRules string) bool {
	return strings.Contains(mainRules, `anchor "`+pfAnchor+`"`)
}

// PfRunning reports whether `pfctl -s info` says the packet filter is on.
func PfRunning(info string) bool {
	for _, line := range strings.Split(info, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Status:") {
			return strings.Contains(line, "Enabled")
		}
	}
	return false
}

// ensureHook references our anchor from pf.conf (idempotent) and reloads the
// main ruleset only when that changed — the reference is what makes pf
// evaluate the anchor at all.
func (m *realManager) ensureHook(ctx context.Context) error {
	pfconf.Mu.Lock()
	defer pfconf.Mu.Unlock()
	path := m.conf()
	cur, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if !pfconf.Has(string(cur), pfHookBegin) {
		next := pfconf.Insert(string(cur), pfHookBegin, pfHookEnd, pfAnchor)
		if err := pfconf.WriteAtomic(path, []byte(next), pfconf.ModeOf(path, 0o644)); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	// Reload even when the file already had the hook: something (a VPN
	// client, an admin) may have loaded a ruleset without it since.
	main, _ := run(ctx, "pfctl", "-s", "rules")
	if !PfHooked(main) {
		if _, err := run(ctx, "pfctl", "-f", path); err != nil {
			return fmt.Errorf("reload %s: %w", path, err)
		}
	}
	return nil
}

// dropHook removes our pf.conf block and reloads, leaving pf as we found it.
func (m *realManager) dropHook(ctx context.Context) error {
	pfconf.Mu.Lock()
	defer pfconf.Mu.Unlock()
	path := m.conf()
	cur, err := os.ReadFile(path)
	if err != nil || !pfconf.Has(string(cur), pfHookBegin) {
		return nil
	}
	next := pfconf.Remove(string(cur), pfHookBegin, pfHookEnd)
	if err := pfconf.WriteAtomic(path, []byte(next), pfconf.ModeOf(path, 0o644)); err != nil {
		return fmt.Errorf("restore %s: %w", path, err)
	}
	_, _ = run(ctx, "pfctl", "-f", path)
	return nil
}

var reEnableToken = regexp.MustCompile(`(?i)token\s*:\s*(\d+)`)

// ensurePFEnabled takes one reference on pf (`pfctl -E` is reference-counted)
// and records its token so Disable releases exactly ours. Previously the
// reference was taken on every enable and never given back.
func (m *realManager) ensurePFEnabled(ctx context.Context) {
	if _, err := os.Stat(m.token()); err == nil {
		return
	}
	out, _ := run(ctx, "pfctl", "-E")
	if t := reEnableToken.FindStringSubmatch(out); t != nil {
		_ = os.WriteFile(m.token(), []byte(t[1]), 0o600)
	}
}

func (m *realManager) releasePF(ctx context.Context) {
	tok, err := os.ReadFile(m.token())
	if err != nil {
		return
	}
	if t := strings.TrimSpace(string(tok)); t != "" {
		_, _ = run(ctx, "pfctl", "-X", t)
	}
	_ = os.Remove(m.token())
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, enableTO)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func runStdin(ctx context.Context, stdin, name string, args ...string) error {
	cctx, cancel := context.WithTimeout(ctx, enableTO)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Stdin = bytes.NewReader([]byte(stdin))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// --- fake ---

// Fake is an in-memory kill switch for tests and the fake provider.
type Fake struct {
	mu      sync.Mutex
	on      bool
	last    Config
	Enables int // how many times Enable ran (re-syncs included)
}

func (f *Fake) Backend() string { return "fake" }

func (f *Fake) Enable(_ context.Context, cfg Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.on, f.last = true, cfg
	f.Enables++
	return nil
}

func (f *Fake) Disable(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.on = false
	return nil
}

func (f *Fake) Enabled(_ context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.on, nil
}

func (f *Fake) Status(_ context.Context) Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return Status{Loaded: f.on, Effective: f.on}
}

// Last is the config most recently applied.
func (f *Fake) Last() Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}
