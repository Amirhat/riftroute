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
	"strings"
	"sync/atomic"
	"time"

	"github.com/Amirhat/riftroute/internal/buildinfo"
	"github.com/Amirhat/riftroute/internal/dns"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/lists"
	"github.com/Amirhat/riftroute/internal/provider"
	"github.com/Amirhat/riftroute/internal/routing"
	"github.com/Amirhat/riftroute/internal/safety"
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
	// updateStatus reports the updater's state (nil = not wired).
	updateStatus func() domain.UpdateStatus
	// wildcardIPs returns the LEARNED addresses for a wildcard rule value
	// (fed by the daemon's DNS learner); nil = apex-only resolution.
	wildcardIPs func(rule string) []string
	// wildcardStatus reports whether the DNS learner is serving and on which
	// port (for the doctor); nil = not wired.
	wildcardStatus func() (bool, int)
	// build identifies the running binary; binWatch reports when a different
	// build has since been installed over it (nil = not wired).
	build    domain.BuildInfo
	binWatch *buildinfo.Watcher
	// tunnelInputs/tunnelStatus read the tunnel manager (nil = no tunnels).
	tunnelInputs func() []routing.TunnelInput
	tunnelStatus func() []domain.TunnelStatus
	// tunnelEngine reports whether tunnels can run here at all (openvpn
	// installed, new enough) and how to install it (doctor).
	tunnelEngine func() domain.TunnelEngine
}

// SetTunnelEngine installs the "can tunnels run here" probe (doctor).
func (s *Service) SetTunnelEngine(fn func() domain.TunnelEngine) { s.tunnelEngine = fn }

// SetTunnels wires the tunnel manager: what its tunnels route, and their
// status for State.
func (s *Service) SetTunnels(inputs func() []routing.TunnelInput, status func() []domain.TunnelStatus) {
	s.tunnelInputs, s.tunnelStatus = inputs, status
}

// TunnelStatuses returns the tunnels' status, marking the routes left out on
// the current network and why (see routing.PlanTunnels). Tunnels that aren't
// running are checked too, so their status says what would be left out.
func (s *Service) TunnelStatuses(ctx context.Context) []domain.TunnelStatus {
	if s.tunnelStatus == nil {
		return nil
	}
	ts := s.tunnelStatus()
	if len(ts) == 0 {
		return ts
	}
	tunnels := append([]routing.TunnelInput(nil), s.tunnels()...)
	running := map[string]bool{}
	for _, t := range tunnels {
		running[t.Name] = true
	}
	for _, t := range ts {
		if !running[t.Name] {
			tunnels = append(tunnels, routing.TunnelInput{Name: t.Name, Routes: t.Routes})
		}
	}
	plan := routing.PlanTunnels(s.networkInput(ctx, tunnels, nil))
	for i := range ts {
		ts[i].Blocked = append(ts[i].Blocked, plan.Blocked[ts[i].Name]...)
	}
	return ts
}

// networkInput is the network side of desired state: the physical gateways,
// the tunnels, and — only when there are tunnels, since it costs kernel and
// resolver reads — what a tunnel route must leave alone: the destinations
// someone else routes, the resolvers in use, the watchdog's anchors. owned is
// what RiftRoute owns (its own routes aren't someone else's); nil reads the
// ownership map.
func (s *Service) networkInput(ctx context.Context, tunnels []routing.TunnelInput, owned []domain.ManagedRoute) routing.DesiredInput {
	in := routing.DesiredInput{Platform: s.Platform(), Tunnels: tunnels, Now: s.now()}
	if gw4, if4, err := s.prov.DefaultGateway(ctx, domain.FamilyV4); err == nil {
		in.GatewayV4, in.PhysIfaceV4 = gw4, if4
	}
	in.GatewayV6, in.PhysIfaceV6, _ = s.prov.DefaultGateway(ctx, domain.FamilyV6)
	if len(tunnels) > 0 {
		if owned == nil {
			owned = s.actualManagedRoutes(ctx)
		}
		in.Occupied = s.occupied(ctx, owned)
		in.DNSServers = s.systemResolvers(ctx)
		for _, a := range safety.DefaultAnchors(in.GatewayV4) {
			if addr, err := netip.ParseAddr(a); err == nil {
				in.Anchors = append(in.Anchors, addr)
			}
		}
	}
	return in
}

// TunnelProtected are the addresses a tunnel's own addressing may never
// cover: the physical gateways, the resolvers in use and the watchdog's
// anchors. A server that gave its tunnel a network (or a point-to-point
// peer) holding one of them would pull that traffic into the tunnel.
func (s *Service) TunnelProtected(ctx context.Context) []netip.Addr {
	var out []netip.Addr
	gw4, _, err := s.prov.DefaultGateway(ctx, domain.FamilyV4)
	if err == nil && gw4.IsValid() {
		out = append(out, gw4)
	}
	if gw6, _, err := s.prov.DefaultGateway(ctx, domain.FamilyV6); err == nil && gw6.IsValid() {
		out = append(out, gw6.WithZone(""))
	}
	out = append(out, s.systemResolvers(ctx)...)
	for _, a := range safety.DefaultAnchors(gw4) {
		if addr, err := netip.ParseAddr(a); err == nil {
			out = append(out, addr)
		}
	}
	return out
}

// systemResolvers are the DNS resolvers in use, less the ones the user
// pointed a domain at (split DNS): those often sit behind a tunnel on purpose
// — the tunnel's internal zone resolving through its own server.
func (s *Service) systemResolvers(ctx context.Context) []netip.Addr {
	cfg, err := s.prov.DNSConfig(ctx)
	if err != nil {
		return nil
	}
	perDomain := map[netip.Addr]bool{}
	if s.store != nil {
		if rs, err := s.store.LoadSplitDNS(); err == nil {
			for _, r := range rs {
				if a, err := netip.ParseAddr(r.Resolver); err == nil {
					perDomain[a.Unmap()] = true
				}
			}
		}
	}
	var out []netip.Addr
	for _, v := range cfg.Servers {
		if a, err := netip.ParseAddr(v); err == nil && !perDomain[a.Unmap()] {
			out = append(out, a.Unmap().WithZone(""))
		}
	}
	return out
}

// occupied maps the main-table destinations someone other than RiftRoute
// routes (masked CIDR → interface), for routing.TunnelRouteBlock. Kernel
// clone entries don't count: a real route replaces them.
func (s *Service) occupied(ctx context.Context, owned []domain.ManagedRoute) map[string]string {
	ours := map[string]bool{}
	for _, o := range owned {
		ours[routing.RouteKey(o.Route)] = true
	}
	out := map[string]string{}
	for _, fam := range []domain.Family{domain.FamilyV4, domain.FamilyV6} {
		rs, _ := s.prov.ListRoutes(ctx, fam)
		for _, r := range rs {
			if r.Table != "" || r.Cloned || r.Owner == domain.OwnerRiftRoute || ours[routing.RouteKey(r)] {
				continue
			}
			if pfx, err := netip.ParsePrefix(r.DstCIDR); err == nil && pfx.Bits() > 0 {
				out[pfx.Masked().String()] = r.Iface
			}
		}
	}
	return out
}

func (s *Service) tunnels() []routing.TunnelInput {
	if s.tunnelInputs == nil {
		return nil
	}
	return s.tunnelInputs()
}

// SetBuild records the running binary's identity and the watcher that
// detects a newer install waiting on a restart.
func (s *Service) SetBuild(b domain.BuildInfo, w *buildinfo.Watcher) {
	s.build, s.binWatch = b, w
}

// Health reports the daemon's identity and liveness without touching the
// provider — cheap enough for /healthz polling.
func (s *Service) Health() domain.Health {
	build := s.build
	if build.Version == "" {
		build.Version = s.version
	}
	h := domain.Health{
		Daemon: domain.DaemonOK, Version: s.version, Provider: s.prov.Name(),
		UptimeSeconds: int64(s.now().Sub(s.started).Seconds()), PID: pid(),
		Build: build, Binary: s.binWatch.Path(), StartedAt: s.started,
	}
	h.RestartRequired, h.RestartReason = s.binWatch.Check()
	if s.store != nil {
		h.SchemaVersion, _ = s.store.UserVersion()
	}
	return h
}

// SetResolver overrides the domain resolver cache (tests).
func (s *Service) SetResolver(c *dns.Cache) { s.domains = c }

// SetKillSwitchStatus installs a callback reporting whether the kill switch is
// active, so State can surface it (the manager lives in the daemon).
func (s *Service) SetKillSwitchStatus(fn func() bool) { s.killStatus = fn }

// SetUpdateStatus wires the updater's status into State (nil: no updater).
func (s *Service) SetUpdateStatus(fn func() domain.UpdateStatus) { s.updateStatus = fn }

// SetWildcardIPs installs the daemon's learned-answer source for wildcard
// domain rules (see internal/dnsproxy).
func (s *Service) SetWildcardIPs(fn func(rule string) []string) { s.wildcardIPs = fn }

// SetWildcardStatus installs the DNS learner's health callback (doctor).
func (s *Service) SetWildcardStatus(fn func() (bool, int)) { s.wildcardStatus = fn }

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
	in := s.networkInput(ctx, s.tunnels(), nil)
	vg4, vi4 := s.resolveVPN(ctx, domain.FamilyV4)
	vg6, vi6 := s.resolveVPN(ctx, domain.FamilyV6)
	in.Profiles = profiles
	in.PolicyRouting = s.prov.Capabilities().PolicyRouting
	in.Lists = s.listsMap()
	in.Domains = s.resolveDomains(ctx, profiles)
	in.VPNGatewayV4, in.VPNIfaceV4 = vg4, vi4
	in.VPNGatewayV6, in.VPNIfaceV6 = vg6, vi6
	routes, rules, err := routing.BuildDesired(in)
	return routes, rules, in.GatewayV4, err
}

// DesiredTunnelsOnly is the desired set for a tunnel transition: owned —
// what RiftRoute owns right now, as the Apply Protocol hands it over under
// its lock (safety.Protocol.ApplyBuilt) — with only the tunnels' routes
// recomputed. Connecting a tunnel is an explicit action that must install its
// routes even with auto-apply off — but it must not apply unrelated profile
// changes that are staged and waiting for the user.
//
// The other owned routes are carried over as they are, placed beside the
// tunnels as a full reconcile would: a route inside a live tunnel's networks
// yields to it, so the set never routes one destination two ways.
func (s *Service) DesiredTunnelsOnly(ctx context.Context, owned []domain.ManagedRoute) ([]domain.ManagedRoute, []domain.ManagedRule, error) {
	if owned == nil {
		owned = []domain.ManagedRoute{} // owns nothing: don't let networkInput read the map again
	}
	in := s.networkInput(ctx, s.tunnels(), owned)
	var others []domain.ManagedRoute
	for _, o := range owned {
		if !strings.HasPrefix(o.ProfileID, routing.TunnelProfilePrefix) {
			others = append(others, o)
		}
	}
	return routing.PlanTunnels(in).Beside(others), s.actualManagedRules(ctx), nil
}

// PhysicalGateway is the resolved v4 physical gateway (zero if none) — what
// an apply's guardrails and watchdog anchor on.
func (s *Service) PhysicalGateway(ctx context.Context) netip.Addr {
	gw, _, err := s.prov.DefaultGateway(ctx, domain.FamilyV4)
	if err != nil {
		return netip.Addr{}
	}
	return gw
}

// TunnelsActive reports whether a tunnel is running, or has routes recorded
// — whether a tunnel apply has anything to keep current or withdraw.
func (s *Service) TunnelsActive(ctx context.Context) bool {
	return len(s.tunnels()) > 0 || s.OwnsTunnelRoutes(ctx)
}

// OwnsTunnelRoutes reports whether RiftRoute has routes recorded for a
// tunnel — at startup, what a daemon that died with tunnels up left behind.
func (s *Service) OwnsTunnelRoutes(ctx context.Context) bool {
	for _, o := range s.actualManagedRoutes(ctx) {
		if strings.HasPrefix(o.ProfileID, routing.TunnelProfilePrefix) {
			return true
		}
	}
	return false
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
			// …plus every subdomain address the DNS learner has observed.
			if s.wildcardIPs != nil && strings.HasPrefix(r.Value, "*.") {
				seen := map[string]bool{}
				for _, v := range ss {
					seen[v] = true
				}
				for _, v := range s.wildcardIPs(r.Value) {
					if !seen[v] {
						seen[v] = true
						ss = append(ss, v)
					}
				}
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

// WildcardRules returns the distinct wildcard domain rule values ("*.x.com")
// across enabled profiles — what the DNS learner should be watching.
func (s *Service) WildcardRules() []string {
	if s.store == nil {
		return nil
	}
	profs, _ := s.store.ListProfiles()
	seen := map[string]bool{}
	var out []string
	for _, p := range profs {
		if !p.Enabled {
			continue
		}
		for _, r := range p.Rules {
			if r.Type == domain.RuleDomain && strings.HasPrefix(r.Value, "*.") && !seen[r.Value] {
				seen[r.Value] = true
				out = append(out, r.Value)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (s *Service) wildcardRuleCount() int { return len(s.WildcardRules()) }

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
	if len(profs) == 0 && len(s.tunnels()) == 0 {
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
	// Tunnel routes the kernel dropped with their interface count as missing
	// (as the Apply Protocol will see them), not as "in sync".
	actualRoutes = routing.VerifyTunnelRoutes(actualRoutes, dRoutes, func(fam domain.Family) ([]domain.Route, error) {
		return s.prov.ListRoutes(ctx, fam)
	})
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

	tunnels := s.TunnelStatuses(ctx)

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
		Health:            s.Health(),
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
		Preferences:       s.Preferences(),
		Update:            s.updateSnapshot(),
		KillSwitchNotice:  s.setting(domain.SettingKillSwitchNotice),
		Tunnels:           tunnels,
		GeneratedAt:       s.now(),
	}, nil
}

func (s *Service) setting(key string) string {
	if s.store == nil {
		return ""
	}
	v, _, _ := s.store.GetSetting(key)
	return v
}

func (s *Service) updateSnapshot() *domain.UpdateStatus {
	if s.updateStatus == nil {
		return nil
	}
	st := s.updateStatus()
	return &st
}

// Preferences returns the user's update/telemetry choices: defaults when
// unset, the conservative choices (notify, telemetry off) when unreadable.
func (s *Service) Preferences() domain.Preferences {
	if s.store == nil {
		return store.ConservativePreferences()
	}
	p, _ := s.store.LoadPreferences()
	return p
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
	h := s.Health()
	h.Daemon, h.Reason = domain.DaemonDegraded, err.Error()
	return domain.State{
		Health:       h,
		Preferences:  s.Preferences(),
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
