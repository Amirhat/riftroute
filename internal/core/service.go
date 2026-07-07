// Package core is the headless heart of the daemon: it assembles the aggregate
// State, answers reads (routes, interfaces, DNS, route-explain), and is the
// single place the API server and (later) the reconciler call into. It depends
// only on the RouteProvider and the Store, so it is fully testable without a
// network, a socket, or root (spec §1.5).
package core

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"sync/atomic"
	"time"

	"github.com/Amirhat/riftroute/internal/dns"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/lists"
	"github.com/Amirhat/riftroute/internal/provider"
	"github.com/Amirhat/riftroute/internal/routing"
	"github.com/Amirhat/riftroute/internal/store"
)

func pid() int { return os.Getpid() }

// Service is the headless application core.
type Service struct {
	prov       provider.RouteProvider
	store      *store.Store
	version    string
	started    time.Time
	now        func() time.Time
	autoApply  atomic.Bool
	domains    *dns.Cache
	killStatus func() bool
}

// SetResolver overrides the domain resolver cache (tests).
func (s *Service) SetResolver(c *dns.Cache) { s.domains = c }

// SetKillSwitchStatus installs a callback reporting whether the kill switch is
// active, so State can surface it (the manager lives in the daemon).
func (s *Service) SetKillSwitchStatus(fn func() bool) { s.killStatus = fn }

// SetAutoApply records whether auto-apply is active (surfaced in State for the
// UI/CLI). Atomic: the Settings toggle flips it from an API handler while State
// reads it concurrently.
func (s *Service) SetAutoApply(on bool) { s.autoApply.Store(on) }

// AutoApply reports whether auto-apply is currently active.
func (s *Service) AutoApply() bool { return s.autoApply.Load() }

// New builds a Service over a provider and store.
func New(prov provider.RouteProvider, st *store.Store, version string) *Service {
	return &Service{
		prov:    prov,
		store:   st,
		version: version,
		started: time.Now(),
		now:     time.Now,
		domains: dns.NewCache(&dns.SystemResolver{}, 60*time.Second),
	}
}

// Provider exposes the underlying provider (used by the daemon for wiring).
func (s *Service) Provider() provider.RouteProvider { return s.prov }

// Platform reports the provider platform ("darwin"|"linux"|"fake").
func (s *Service) Platform() string { return s.prov.Capabilities().Platform }

// Store exposes the persistence layer (used by the daemon for wiring).
func (s *Service) Store() *store.Store { return s.store }

// DesiredManaged builds the managed routes + rules implied by the enabled
// profiles, resolving the physical gateway from the provider (spec §2.2 step 1 /
// §4.4). It also returns the v4 physical gateway for guardrail checks.
func (s *Service) DesiredManaged(ctx context.Context) ([]domain.ManagedRoute, []domain.ManagedRule, netip.Addr, error) {
	var profiles []domain.Profile
	if s.store != nil {
		profiles, _ = s.store.ListProfiles()
	}
	return s.DesiredFromProfiles(ctx, profiles)
}

// DesiredFromProfiles builds desired managed routes + rules from an explicit
// profile set (used by config dry-run before anything is persisted).
func (s *Service) DesiredFromProfiles(ctx context.Context, profiles []domain.Profile) ([]domain.ManagedRoute, []domain.ManagedRule, netip.Addr, error) {
	gw4, if4, err4 := s.prov.DefaultGateway(ctx, domain.FamilyV4)
	gw6, if6, _ := s.prov.DefaultGateway(ctx, domain.FamilyV6)
	vg4, vi4 := s.resolveVPN(ctx, domain.FamilyV4)
	vg6, vi6 := s.resolveVPN(ctx, domain.FamilyV6)
	in := routing.DesiredInput{
		Profiles:      profiles,
		Platform:      s.Platform(),
		PolicyRouting: s.prov.Capabilities().PolicyRouting,
		Lists:         s.listsMap(),
		Domains:       s.resolveDomains(ctx, profiles),
		VPNGatewayV4:  vg4, VPNIfaceV4: vi4,
		VPNGatewayV6: vg6, VPNIfaceV6: vi6,
		Now: s.now(),
	}
	if err4 == nil {
		in.GatewayV4, in.PhysIfaceV4 = gw4, if4
	}
	in.GatewayV6, in.PhysIfaceV6 = gw6, if6
	routes, rules, err := routing.BuildDesired(in)
	return routes, rules, gw4, err
}

// resolveDomains resolves the enabled profiles' domain rules via the TTL cache,
// returning domain → resolved IP strings for the engine to expand.
func (s *Service) resolveDomains(ctx context.Context, profiles []domain.Profile) map[string][]string {
	m := map[string][]string{}
	if s.domains == nil {
		return m
	}
	for _, p := range profiles {
		if !p.Enabled {
			continue
		}
		for _, r := range p.Rules {
			if r.Type != domain.RuleDomain {
				continue
			}
			var ss []string
			// Wildcards resolve their apex (DNS can't enumerate subdomains);
			// the map stays keyed by the raw rule value the engine looks up.
			for _, a := range s.domains.Lookup(ctx, domain.DomainRuleHost(r.Value)) {
				ss = append(ss, a.String())
			}
			m[r.Value] = ss
		}
	}
	return m
}

// DomainHosts returns the distinct domains referenced by enabled profiles (for
// the background re-resolver).
func (s *Service) DomainHosts() []string {
	seen := map[string]bool{}
	var out []string
	if s.store == nil {
		return out
	}
	profs, _ := s.store.ListProfiles()
	for _, p := range profs {
		if !p.Enabled {
			continue
		}
		for _, r := range p.Rules {
			if r.Type != domain.RuleDomain {
				continue
			}
			if h := domain.DomainRuleHost(r.Value); !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	return out
}

// RefreshDomains re-resolves all referenced domains and reports whether any
// answer changed (the daemon reconciles on change — spec §6 re-resolver).
func (s *Service) RefreshDomains(ctx context.Context) bool {
	if s.domains == nil {
		return false
	}
	return s.domains.Refresh(ctx, s.DomainHosts())
}

// AppCgroups returns the distinct per-app rule values across enabled
// include-mode profiles — on Linux these are cgroup v2 paths, the
// classification set the nft marker installs (spec §6). Sorted for stable
// change detection.
func (s *Service) AppCgroups() []string {
	if s.store == nil {
		return nil
	}
	profs, _ := s.store.ListProfiles()
	seen := map[string]bool{}
	var out []string
	for _, p := range profs {
		if !p.Enabled || p.Mode != domain.ModeInclude {
			continue
		}
		for _, r := range p.Rules {
			if r.Type == domain.RuleApp && r.Value != "" && !seen[r.Value] {
				seen[r.Value] = true
				out = append(out, r.Value)
			}
		}
	}
	sort.Strings(out)
	return out
}

// listsMap returns each list's effective entries (static + fetched) for the
// engine to expand profile list references.
func (s *Service) listsMap() map[string][]string {
	m := map[string][]string{}
	if s.store == nil {
		return m
	}
	ls, _ := s.store.ListLists()
	for _, l := range ls {
		m[l.Name] = l.Entries()
	}
	return m
}

// Lists returns all configured lists (with cache metadata).
func (s *Service) Lists() ([]domain.List, error) {
	if s.store == nil {
		return nil, nil
	}
	return s.store.ListLists()
}

// RefreshList fetches a remote list and updates its cache + checksum (spec §5.1).
func (s *Service) RefreshList(ctx context.Context, name string) (domain.List, error) {
	if s.store == nil {
		return domain.List{}, fmt.Errorf("no store")
	}
	l, err := s.store.GetList(name)
	if err != nil {
		return domain.List{}, err
	}
	if l.Source == "" {
		return l, fmt.Errorf("list %q is static (no remote source to refresh)", name)
	}
	entries, checksum, err := lists.Fetch(ctx, l.Source)
	if err != nil {
		return l, err
	}
	now := s.now()
	l.Resolved = entries
	l.Checksum = checksum
	l.LastFetched = &now
	if err := s.store.UpsertList(l); err != nil {
		return l, err
	}
	return l, nil
}

// RefreshAllLists refreshes every remote list, returning the count refreshed.
func (s *Service) RefreshAllLists(ctx context.Context) (int, error) {
	ls, err := s.Lists()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, l := range ls {
		if l.Source == "" {
			continue
		}
		if _, err := s.RefreshList(ctx, l.Name); err == nil {
			n++
		}
	}
	return n, nil
}

// computeDrift returns the desired-vs-actual delta over managed routes+rules —
// the single source of truth for the drift shown in State, the doctor, and the
// dashboard. Skipped (empty) when no profiles exist.
func (s *Service) computeDrift(ctx context.Context, actualRoutes []domain.ManagedRoute) domain.DriftStatus {
	d := domain.DriftStatus{}
	if s.store == nil {
		return d
	}
	profs, _ := s.store.ListProfiles()
	if len(profs) == 0 {
		return d
	}
	dRoutes, dRules, _, err := s.DesiredFromProfiles(ctx, profs)
	if err != nil {
		// Desired state can't even be computed (e.g. include mode with no live
		// tunnel). Report attention-needed instead of a false "in sync" — the
		// installed rules keep fail-safing meanwhile.
		d.Pending = true
		d.Reason = err.Error()
		return d
	}
	plan := routing.Reconcile(dRoutes, actualRoutes, dRules, s.actualManagedRules(ctx), s.Platform())
	for _, op := range plan.Ops {
		switch op.Kind {
		case domain.OpAddRoute, domain.OpAddRule:
			d.Adds++
		case domain.OpDelRoute, domain.OpDelRule:
			d.Dels++
		}
	}
	d.Pending = len(plan.Ops) > 0
	return d
}

// actualManagedRoutes returns the routes RiftRoute owns. The persistent
// ownership map is the source of truth — the same one the apply protocol
// reconciles against — because kernel owner tags only exist on Linux (proto
// riftroute); a provider tag-scan on macOS sees nothing and would report
// "0 managed / drift pending" forever. Falls back to the tag-scan when there
// is no store (tests) or the read fails.
func (s *Service) actualManagedRoutes(ctx context.Context) []domain.ManagedRoute {
	if s.store != nil {
		if owned, err := s.store.ListOwned(); err == nil {
			return owned
		}
	}
	var out []domain.ManagedRoute
	for _, fam := range []domain.Family{domain.FamilyV4, domain.FamilyV6} {
		rs, err := s.prov.ListRoutes(ctx, fam)
		if err != nil {
			continue
		}
		for _, r := range rs {
			if r.Owner == domain.OwnerRiftRoute {
				out = append(out, domain.ManagedRoute{Route: r, ProfileID: r.Profile})
			}
		}
	}
	return out
}

// actualManagedRules returns the policy rules RiftRoute owns (proto-tagged).
func (s *Service) actualManagedRules(ctx context.Context) []domain.ManagedRule {
	var out []domain.ManagedRule
	for _, fam := range []domain.Family{domain.FamilyV4, domain.FamilyV6} {
		rs, err := s.prov.ListRules(ctx, fam)
		if err != nil {
			continue
		}
		for _, r := range rs {
			if r.Proto == "riftroute" {
				out = append(out, domain.ManagedRule{PolicyRule: r})
			}
		}
	}
	return out
}

// resolveVPN finds the active tunnel next-hop+iface for a family — the current
// default route that egresses a VPN interface (spec §5.4 include mode). Returns
// a zero gateway for an on-link (point-to-point) tunnel default.
func (s *Service) resolveVPN(ctx context.Context, fam domain.Family) (netip.Addr, string) {
	ifaces, _ := s.prov.Interfaces(ctx)
	vpn := map[string]bool{}
	for _, ifc := range ifaces {
		if ifc.IsVPN && ifc.Up {
			vpn[ifc.Name] = true
		}
	}
	def := "0.0.0.0/0"
	if fam == domain.FamilyV6 {
		def = "::/0"
	}
	routes, _ := s.prov.ListRoutes(ctx, fam)
	for _, r := range routes {
		if r.Table == "" && r.DstCIDR == def && vpn[r.Iface] {
			gw, _ := netip.ParseAddr(r.Gateway) // zero if on-link
			return gw, r.Iface
		}
	}
	return netip.Addr{}, ""
}

// State assembles the full aggregate state for the dashboard/status (spec §11).
func (s *Service) State(ctx context.Context) (domain.State, error) {
	ifaces, err := s.prov.Interfaces(ctx)
	if err != nil {
		return s.degraded(err), nil
	}
	vpnByIface := map[string]bool{}
	var vpnUp []string
	for _, ifc := range ifaces {
		vpnByIface[ifc.Name] = ifc.IsVPN
		if ifc.IsVPN && ifc.Up {
			vpnUp = append(vpnUp, ifc.Name)
		}
	}

	v4, _ := s.prov.ListRoutes(ctx, domain.FamilyV4)
	v6, _ := s.prov.ListRoutes(ctx, domain.FamilyV6)

	defaults := []domain.DefaultRoute{
		defaultFor(v4, domain.FamilyV4, "0.0.0.0/0", vpnByIface),
		defaultFor(v6, domain.FamilyV6, "::/0", vpnByIface),
	}

	actualManaged := s.actualManagedRoutes(ctx)
	managed := len(actualManaged)
	managedRules := len(s.actualManagedRules(ctx))

	// Live drift: desired (enabled profiles) vs actual managed. Skipped when no
	// profiles exist to avoid resolving the gateway on every state push.
	drift := s.computeDrift(ctx, actualManaged)

	dns, _ := s.prov.DNSConfig(ctx)

	var profs []domain.ProfileStatus
	if s.store != nil {
		ps, _ := s.store.ListProfiles()
		for _, p := range ps {
			profs = append(profs, domain.ProfileStatus{
				ID: p.ID, Name: p.Name, Enabled: p.Enabled, Mode: p.Mode,
				RuleCount: len(p.Rules),
				// Applied is computed by the reconciler (M2+); false for now.
			})
		}
	}

	return domain.State{
		Health: domain.Health{
			Daemon: domain.DaemonOK, Version: s.version, Provider: s.prov.Name(),
			UptimeSeconds: int64(s.now().Sub(s.started).Seconds()), PID: pid(),
		},
		Capabilities:      s.prov.Capabilities(),
		VPN:               domain.VPNStatus{Active: len(vpnUp) > 0, Interfaces: vpnUp},
		Interfaces:        ifaces,
		Defaults:          defaults,
		DNS:               dns,
		Profiles:          profs,
		Drift:             drift,
		ManagedRouteCount: managed,
		ManagedRuleCount:  managedRules,
		AutoApply:         s.autoApply.Load(),
		KillSwitch:        s.killStatus != nil && s.killStatus(),
		GeneratedAt:       s.now(),
	}, nil
}

// Routes returns the routing table in kernel lookup-precedence order,
// optionally filtered by family and owner. Ownership is enriched from the
// persistent map before filtering — macOS kernel routes carry no owner tag,
// so without the join every managed route would render as "system" there.
func (s *Service) Routes(ctx context.Context, family domain.Family, owner domain.Owner) ([]domain.Route, error) {
	var out []domain.Route
	fams := []domain.Family{family}
	if family == "" {
		fams = []domain.Family{domain.FamilyV4, domain.FamilyV6}
	}
	for _, f := range fams {
		rs, err := s.prov.ListRoutes(ctx, f)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	s.tagOwnedRoutes(out)
	if owner != "" {
		filtered := out[:0]
		for _, r := range out {
			if r.Owner == owner {
				filtered = append(filtered, r)
			}
		}
		out = filtered
	}
	sortLookupOrder(out)
	return out, nil
}

// tagOwnedRoutes stamps Owner/Profile onto listed routes that appear in the
// ownership map (matched by full route identity).
func (s *Service) tagOwnedRoutes(rs []domain.Route) {
	if s.store == nil {
		return
	}
	owned, err := s.store.ListOwned()
	if err != nil || len(owned) == 0 {
		return
	}
	byKey := make(map[string]domain.ManagedRoute, len(owned))
	for _, mr := range owned {
		byKey[routing.RouteKey(mr.Route)] = mr
	}
	for i := range rs {
		if mr, ok := byKey[routing.RouteKey(rs[i])]; ok {
			rs[i].Owner = domain.OwnerRiftRoute
			if rs[i].Profile == "" {
				rs[i].Profile = mr.ProfileID
			}
		}
	}
}

// sortLookupOrder orders routes the way the kernel evaluates a destination:
// v4 before v6, longest (most specific) prefix first, then lowest metric,
// then destination for a stable tiebreak. Unparseable destinations sort last.
func sortLookupOrder(rs []domain.Route) {
	sort.SliceStable(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if a.Family != b.Family {
			return a.Family == domain.FamilyV4
		}
		if pa, pb := prefixBits(a.DstCIDR), prefixBits(b.DstCIDR); pa != pb {
			return pa > pb
		}
		if a.Metric != b.Metric {
			return a.Metric < b.Metric
		}
		return a.DstCIDR < b.DstCIDR
	})
}

func prefixBits(cidr string) int {
	if p, err := netip.ParsePrefix(cidr); err == nil {
		return p.Bits()
	}
	if a, err := netip.ParseAddr(cidr); err == nil { // bare host address
		return a.BitLen()
	}
	return -1
}

// Rules returns policy rules (Linux ip rules / macOS PF anchor rules). An
// empty family returns both v4 and v6.
func (s *Service) Rules(ctx context.Context, family domain.Family) ([]domain.PolicyRule, error) {
	fams := []domain.Family{family}
	if family == "" {
		fams = []domain.Family{domain.FamilyV4, domain.FamilyV6}
	}
	var out []domain.PolicyRule
	seen := map[string]bool{}
	for _, f := range fams {
		rs, err := s.prov.ListRules(ctx, f)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			// PF anchor reads are family-agnostic on macOS; dedupe across passes.
			if k := routing.RuleKey(r); !seen[k] {
				seen[k] = true
				out = append(out, r)
			}
		}
	}
	return out, nil
}

// Interfaces returns the interface list.
func (s *Service) Interfaces(ctx context.Context) ([]domain.Iface, error) {
	return s.prov.Interfaces(ctx)
}

// DNS returns the resolver configuration.
func (s *Service) DNS(ctx context.Context) (domain.DNSState, error) {
	return s.prov.DNSConfig(ctx)
}

// Explain answers "where does traffic to target go, and why?" — the killer
// debugging tool (spec §7.2): the kernel's real decision beside RiftRoute's
// simulated decision over desired state, with drift highlighted. Domain targets
// are not yet resolved (M5).
func (s *Service) Explain(ctx context.Context, target string) (domain.RouteExplain, error) {
	out := domain.RouteExplain{Target: target}
	addr, err := netip.ParseAddr(target)
	if err != nil {
		// Treat as a domain: resolve and explain the first address (spec §7.2).
		if s.domains == nil {
			out.Note = "no resolver available"
			return out, nil
		}
		addrs := s.domains.Lookup(ctx, target)
		for _, a := range addrs {
			out.Resolved = append(out.Resolved, a.String())
		}
		if len(addrs) == 0 {
			out.Note = "could not resolve " + target
			return out, nil
		}
		addr = addrs[0]
		if len(addrs) > 1 {
			out.Note = "showing the decision for the first of " + fmt.Sprint(len(addrs)) + " resolved addresses"
		}
	}

	dec, err := s.prov.LookupRoute(ctx, addr)
	if err != nil {
		return out, err
	}
	out.Kernel = dec

	// Simulated decision: LPM over (current foreign routes + desired managed
	// routes) — i.e. what the table would be once reconciled to desired.
	fam := domain.FamilyV4
	if addr.Is6() {
		fam = domain.FamilyV6
	}
	cur, _ := s.prov.ListRoutes(ctx, fam)
	overlay := make([]domain.Route, 0, len(cur))
	for _, r := range cur {
		if r.Owner != domain.OwnerRiftRoute {
			overlay = append(overlay, r)
		}
	}
	if desired, _, _, derr := s.DesiredManaged(ctx); derr == nil {
		for _, mr := range desired {
			if mr.Route.Family == fam && mr.Route.Table == "" {
				overlay = append(overlay, mr.Route)
			}
		}
	}
	vpnByIface := s.vpnByIface(ctx)
	sim := routing.Simulate(overlay, addr, vpnByIface)
	out.Simulated = &sim
	out.Drift = routing.Drift(dec, sim)
	return out, nil
}

func (s *Service) vpnByIface(ctx context.Context) map[string]bool {
	m := map[string]bool{}
	ifaces, err := s.prov.Interfaces(ctx)
	if err != nil {
		return m
	}
	for _, ifc := range ifaces {
		m[ifc.Name] = ifc.IsVPN
	}
	return m
}

// Conflicts reports overlapping desired routes with different next hops (§7.8).
func (s *Service) Conflicts(ctx context.Context) ([]domain.Conflict, error) {
	desired, _, _, err := s.DesiredManaged(ctx)
	if err != nil {
		return nil, err
	}
	return routing.DetectConflicts(desired), nil
}

// Diff computes the desired-vs-actual difference over MANAGED routes (spec §7.3).
// In M1 there is no reconciler, so desired is empty: a system with no
// RiftRoute-owned routes is reported InSync. Once the engine lands (M2) desired
// is derived from enabled profiles and this gains add/change entries.
func (s *Service) Diff(ctx context.Context) (domain.Diff, error) {
	var actualManaged []domain.Route
	for _, fam := range []domain.Family{domain.FamilyV4, domain.FamilyV6} {
		rs, err := s.prov.ListRoutes(ctx, fam)
		if err != nil {
			continue
		}
		for _, r := range rs {
			if r.Owner == domain.OwnerRiftRoute {
				actualManaged = append(actualManaged, r)
			}
		}
	}
	d := domain.Diff{}
	// desired is empty in M1 → every managed route would be removed to converge.
	for _, r := range actualManaged {
		d.Entries = append(d.Entries, domain.DiffEntry{Action: domain.DiffDel, Route: r})
		d.Dels++
	}
	d.InSync = len(d.Entries) == 0
	return d, nil
}

func (s *Service) degraded(err error) domain.State {
	return domain.State{
		Health: domain.Health{
			Daemon: domain.DaemonDegraded, Reason: err.Error(), Version: s.version,
			Provider: s.prov.Name(), UptimeSeconds: int64(s.now().Sub(s.started).Seconds()), PID: pid(),
		},
		Capabilities: s.prov.Capabilities(),
		GeneratedAt:  s.now(),
	}
}

func defaultFor(routes []domain.Route, fam domain.Family, defCIDR string, vpnByIface map[string]bool) domain.DefaultRoute {
	for _, r := range routes {
		if r.Table == "" && r.DstCIDR == defCIDR {
			return domain.DefaultRoute{
				Family: fam, Present: true, Gateway: r.Gateway, Iface: r.Iface,
				Owner: r.Owner, ViaVPN: vpnByIface[r.Iface],
			}
		}
	}
	return domain.DefaultRoute{Family: fam, Present: false, Owner: domain.OwnerUnknown}
}
