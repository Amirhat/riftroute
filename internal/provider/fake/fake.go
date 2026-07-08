// Package fake is an in-memory RouteProvider with a fully simulated routing
// table, rule set, and interface list (spec §4.6). It lets the engine,
// reconciler, watchdog, and Apply Protocol be exercised with zero risk to any
// host. In M0 it also backs the daemon in dev so the whole UI/CLI/daemon spine
// can be developed without root or a real network.
package fake

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"sync"

	"github.com/Amirhat/riftroute/internal/domain"
)

// Provider is a thread-safe in-memory RouteProvider.
type Provider struct {
	mu         sync.Mutex
	ifaces     []domain.Iface
	routesV4   []domain.Route
	routesV6   []domain.Route
	rules      []domain.PolicyRule
	dns        domain.DNSState
	physGW     map[domain.Family]netip.Addr
	physIface  string
	caps       domain.Capabilities
	managedKey map[string]bool // routeKey -> owned, for FlushOwned/ownership

	// failure injection (tests): a CIDR present here makes the matching op error,
	// to exercise mid-apply rollback (spec §2.5).
	failAdd map[string]bool
	failDel map[string]bool
}

// New returns a fake provider seeded with a realistic split-tunnel scenario: a
// physical LAN (en0 via 192.168.1.1), an active VPN (utun3) owning the default
// route, and loopback. This is the canonical "VPN is up" situation RiftRoute
// exists to manage.
func New() *Provider {
	p := &Provider{
		managedKey: map[string]bool{},
		failAdd:    map[string]bool{},
		failDel:    map[string]bool{},
		physGW: map[domain.Family]netip.Addr{
			domain.FamilyV4: netip.MustParseAddr("192.168.1.1"),
		},
		physIface: "en0",
		caps: domain.Capabilities{
			Platform:      "fake",
			PolicyRouting: true,
			Fwmark:        true,
			PerAppRouting: true,
			ProtoTag:      true,
			IPv6:          true,
			KillSwitch:    true,
			IfaceScoping:  true,
			Backend:       "fake",
		},
		dns: domain.DNSState{
			Servers:       []string{"10.8.0.1"},
			SearchDomains: []string{"corp.example.com"},
			Iface:         "utun3",
		},
		ifaces: []domain.Iface{
			{Name: "lo0", Up: true, Kind: domain.IfaceKindLoopback, Addrs: []string{"127.0.0.1/8", "::1/128"}, MTU: 16384},
			{Name: "en0", Up: true, Kind: domain.IfaceKindPhysical, Addrs: []string{"192.168.1.50/24", "fe80::1c%en0/64"}, MTU: 1500},
			{Name: "utun3", Up: true, Kind: domain.IfaceKindUtun, Addrs: []string{"10.8.0.2/32"}, MTU: 1400, IsVPN: true},
		},
		routesV4: []domain.Route{
			{DstCIDR: "0.0.0.0/0", Gateway: "10.8.0.1", Iface: "utun3", Metric: 0, Family: domain.FamilyV4, Owner: domain.OwnerVPN},
			{DstCIDR: "10.8.0.0/24", Gateway: "", Iface: "utun3", Metric: 0, Family: domain.FamilyV4, Owner: domain.OwnerVPN},
			{DstCIDR: "192.168.1.0/24", Gateway: "", Iface: "en0", Metric: 0, Family: domain.FamilyV4, Owner: domain.OwnerSystem},
			{DstCIDR: "127.0.0.0/8", Gateway: "", Iface: "lo0", Metric: 0, Family: domain.FamilyV4, Owner: domain.OwnerSystem},
		},
		routesV6: []domain.Route{
			{DstCIDR: "::1/128", Gateway: "", Iface: "lo0", Metric: 0, Family: domain.FamilyV6, Owner: domain.OwnerSystem},
			{DstCIDR: "fe80::/64", Gateway: "", Iface: "en0", Metric: 0, Family: domain.FamilyV6, Owner: domain.OwnerSystem},
		},
		rules: []domain.PolicyRule{
			{Priority: 0, Selector: "from all", Table: "local", Family: domain.FamilyV4},
			{Priority: 32766, Selector: "from all", Table: "main", Family: domain.FamilyV4},
			{Priority: 32767, Selector: "from all", Table: "default", Family: domain.FamilyV4},
		},
	}
	return p
}

func (p *Provider) Name() string { return "fake" }

func (p *Provider) Capabilities() domain.Capabilities { return p.caps }

func (p *Provider) ListRoutes(_ context.Context, family domain.Family) ([]domain.Route, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch family {
	case domain.FamilyV4:
		return cloneRoutes(p.routesV4), nil
	case domain.FamilyV6:
		return cloneRoutes(p.routesV6), nil
	default:
		return nil, fmt.Errorf("fake: unknown family %q", family)
	}
}

func (p *Provider) ListRules(_ context.Context, family domain.Family) ([]domain.PolicyRule, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := []domain.PolicyRule{}
	for _, r := range p.rules {
		if r.Family == family {
			out = append(out, r)
		}
	}
	return out, nil
}

func (p *Provider) DNSConfig(_ context.Context) (domain.DNSState, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dns, nil
}

func (p *Provider) Interfaces(_ context.Context) ([]domain.Iface, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]domain.Iface, len(p.ifaces))
	copy(out, p.ifaces)
	return out, nil
}

func (p *Provider) DefaultGateway(_ context.Context, family domain.Family) (netip.Addr, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	gw, ok := p.physGW[family]
	if !ok {
		return netip.Addr{}, "", fmt.Errorf("fake: no physical gateway for %s", family)
	}
	return gw, p.physIface, nil
}

// LookupRoute performs a longest-prefix-match over the simulated table — the
// same answer the kernel would give via `route get` / `ip route get`.
func (p *Provider) LookupRoute(_ context.Context, dst netip.Addr) (domain.RouteDecision, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	fam := domain.FamilyV4
	routes := p.routesV4
	if dst.Is6() {
		fam = domain.FamilyV6
		routes = p.routesV6
	}

	best := -1
	bestBits := -1
	for i, r := range routes {
		pfx, err := netip.ParsePrefix(r.DstCIDR)
		if err != nil {
			continue
		}
		if pfx.Contains(dst) && pfx.Bits() > bestBits {
			best = i
			bestBits = pfx.Bits()
		}
	}

	dec := domain.RouteDecision{
		Target:    dst.String(),
		Source:    "kernel",
		Family:    fam,
		Reachable: best >= 0,
	}
	if best >= 0 {
		r := routes[best]
		dec.MatchedCIDR = r.DstCIDR
		dec.Gateway = r.Gateway
		dec.Iface = r.Iface
		dec.Owner = r.Owner
		dec.Profile = r.Profile
		dec.ViaVPN = ifaceIsVPN(p.ifaces, r.Iface)
	}
	return dec, nil
}

// --- Mutations ---

func (p *Provider) AddRoute(_ context.Context, r domain.ManagedRoute) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failAdd[r.Route.DstCIDR] {
		return fmt.Errorf("fake: injected AddRoute failure for %s", r.Route.DstCIDR)
	}
	rt := r.Route
	if r.ProfileID != "" {
		// Policy-managed add: tagged ours, like `ip route add proto riftroute`.
		rt.Owner = domain.OwnerRiftRoute
		rt.Proto = "riftroute"
		rt.Profile = r.ProfileID
	} else if rt.Owner == "" {
		// External add (route-op edit): the kernel keeps the route's own
		// identity — it does NOT become RiftRoute-managed.
		rt.Owner = domain.OwnerSystem
	}
	key := routeKey(rt)
	if p.indexOf(rt) >= 0 {
		// idempotent: already present
		if r.ProfileID != "" {
			p.managedKey[key] = true
		}
		return nil
	}
	p.appendRoute(rt)
	if r.ProfileID != "" {
		p.managedKey[key] = true
	}
	return nil
}

func (p *Provider) DelRoute(_ context.Context, r domain.ManagedRoute) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failDel[r.Route.DstCIDR] {
		return fmt.Errorf("fake: injected DelRoute failure for %s", r.Route.DstCIDR)
	}
	// External delete (route-op, no owning profile): the kernel deletes any
	// route that exists — match by destination identity as listed.
	if r.ProfileID == "" {
		rt := r.Route
		if idx := p.indexOf(rt); idx >= 0 {
			p.removeRoute(rt.Family, idx)
			delete(p.managedKey, routeKey(rt))
			return nil
		}
		// Try the managed rendering of the same route (owner/proto stamped).
		rt.Owner = domain.OwnerRiftRoute
		rt.Proto = "riftroute"
		if idx := p.indexOf(rt); idx >= 0 {
			p.removeRoute(rt.Family, idx)
			delete(p.managedKey, routeKey(rt))
			return nil
		}
		return nil // idempotent: already gone
	}
	rt := r.Route
	rt.Owner = domain.OwnerRiftRoute
	rt.Proto = "riftroute"
	rt.Profile = r.ProfileID
	key := routeKey(rt)
	if !p.managedKey[key] {
		// ownership invariant: a POLICY delete must never touch a route we
		// don't own (reconcile-bug tripwire; user route-ops carry no profile
		// and take the external path above).
		return fmt.Errorf("fake: refusing to delete unowned route %s", rt.DstCIDR)
	}
	idx := p.indexOf(rt)
	if idx < 0 {
		delete(p.managedKey, key)
		return nil // idempotent
	}
	p.removeRoute(rt.Family, idx)
	delete(p.managedKey, key)
	return nil
}

func (p *Provider) AddRule(_ context.Context, r domain.ManagedRule) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	pr := r.PolicyRule
	pr.Proto = "riftroute"
	p.rules = append(p.rules, pr)
	sort.SliceStable(p.rules, func(i, j int) bool { return p.rules[i].Priority < p.rules[j].Priority })
	return nil
}

func (p *Provider) DelRule(_ context.Context, r domain.ManagedRule) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, pr := range p.rules {
		// Full rule identity, including the route-to target: two rules steering the
		// same selector into different tunnels (or gateways) must stay distinct, or
		// a tunnel-switch reconcile could delete the freshly added rule.
		if pr.Priority == r.Priority && pr.Selector == r.Selector && pr.Table == r.Table && pr.Family == r.Family &&
			pr.RouteToIface == r.RouteToIface && pr.RouteToGW == r.RouteToGW {
			p.rules = append(p.rules[:i], p.rules[i+1:]...)
			return nil
		}
	}
	return nil // idempotent
}

func (p *Provider) FlushOwned(_ context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.routesV4 = filterOwned(p.routesV4)
	p.routesV6 = filterOwned(p.routesV6)
	kept := p.rules[:0]
	for _, r := range p.rules {
		if r.Proto != "riftroute" {
			kept = append(kept, r)
		}
	}
	p.rules = kept
	p.managedKey = map[string]bool{}
	return nil
}

// FailAddRoute makes a subsequent AddRoute for cidr return an error (tests).
func (p *Provider) FailAddRoute(cidr string, fail bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failAdd[cidr] = fail
}

// FailDelRoute makes a subsequent DelRoute for cidr return an error (tests).
func (p *Provider) FailDelRoute(cidr string, fail bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failDel[cidr] = fail
}

// CountManaged returns how many RiftRoute-owned routes are currently installed.
func (p *Provider) CountManaged() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, r := range append(append([]domain.Route{}, p.routesV4...), p.routesV6...) {
		if r.Owner == domain.OwnerRiftRoute {
			n++
		}
	}
	return n
}

// --- test/dev helpers (not part of RouteProvider) ---

// SetVPN brings the simulated VPN default route up or down, used to exercise the
// auto-apply path in later milestones.
func (p *Provider) SetVPN(up bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.ifaces {
		if p.ifaces[i].Name == "utun3" {
			p.ifaces[i].Up = up
		}
	}
	if up {
		// A VPN coming up SEIZES the default route (as real clients do) — replace
		// whatever default exists (e.g. the physical one installed on the way down),
		// otherwise a down→up cycle would leave the tunnel default missing forever.
		if idx := p.indexOfCIDR(domain.FamilyV4, "0.0.0.0/0"); idx >= 0 {
			p.routesV4 = append(p.routesV4[:idx], p.routesV4[idx+1:]...)
		}
		p.routesV4 = append([]domain.Route{{DstCIDR: "0.0.0.0/0", Gateway: "10.8.0.1", Iface: "utun3", Family: domain.FamilyV4, Owner: domain.OwnerVPN}}, p.routesV4...)
	} else {
		if idx := p.indexOfCIDR(domain.FamilyV4, "0.0.0.0/0"); idx >= 0 {
			p.routesV4 = append(p.routesV4[:idx], p.routesV4[idx+1:]...)
		}
		// physical gateway reclaims the default
		p.routesV4 = append(p.routesV4, domain.Route{DstCIDR: "0.0.0.0/0", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4, Owner: domain.OwnerSystem})
	}
}

// --- internals (caller holds p.mu) ---

func (p *Provider) appendRoute(rt domain.Route) {
	if rt.Family == domain.FamilyV6 {
		p.routesV6 = append(p.routesV6, rt)
		return
	}
	p.routesV4 = append(p.routesV4, rt)
}

func (p *Provider) removeRoute(fam domain.Family, idx int) {
	if fam == domain.FamilyV6 {
		p.routesV6 = append(p.routesV6[:idx], p.routesV6[idx+1:]...)
		return
	}
	p.routesV4 = append(p.routesV4[:idx], p.routesV4[idx+1:]...)
}

func (p *Provider) indexOf(rt domain.Route) int {
	routes := p.routesV4
	if rt.Family == domain.FamilyV6 {
		routes = p.routesV6
	}
	for i, r := range routes {
		if r.DstCIDR == rt.DstCIDR && r.Gateway == rt.Gateway && r.Iface == rt.Iface && r.Table == rt.Table {
			return i
		}
	}
	return -1
}

func (p *Provider) indexOfCIDR(fam domain.Family, cidr string) int {
	routes := p.routesV4
	if fam == domain.FamilyV6 {
		routes = p.routesV6
	}
	for i, r := range routes {
		if r.DstCIDR == cidr {
			return i
		}
	}
	return -1
}

func cloneRoutes(in []domain.Route) []domain.Route {
	out := make([]domain.Route, len(in))
	copy(out, in)
	return out
}

func filterOwned(in []domain.Route) []domain.Route {
	out := in[:0:0]
	for _, r := range in {
		if r.Owner != domain.OwnerRiftRoute {
			out = append(out, r)
		}
	}
	return out
}

func routeKey(r domain.Route) string {
	return string(r.Family) + "|" + r.Table + "|" + r.DstCIDR + "|" + r.Gateway + "|" + r.Iface
}

func ifaceIsVPN(ifaces []domain.Iface, name string) bool {
	for _, i := range ifaces {
		if i.Name == name {
			return i.IsVPN
		}
	}
	return false
}
