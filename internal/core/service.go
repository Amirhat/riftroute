// Package core is the headless heart of the daemon: it assembles the aggregate
// State, answers reads (routes, interfaces, DNS, route-explain), and is the
// single place the API server and (later) the reconciler call into. It depends
// only on the RouteProvider and the Store, so it is fully testable without a
// network, a socket, or root (spec §1.5).
package core

import (
	"context"
	"net/netip"
	"os"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider"
	"github.com/Amirhat/riftroute/internal/routing"
	"github.com/Amirhat/riftroute/internal/store"
)

func pid() int { return os.Getpid() }

// Service is the headless application core.
type Service struct {
	prov      provider.RouteProvider
	store     *store.Store
	version   string
	started   time.Time
	now       func() time.Time
	autoApply bool
}

// SetAutoApply records whether the daemon's auto-apply loop is active (surfaced
// in State for the UI/CLI).
func (s *Service) SetAutoApply(on bool) { s.autoApply = on }

// New builds a Service over a provider and store.
func New(prov provider.RouteProvider, st *store.Store, version string) *Service {
	return &Service{
		prov:    prov,
		store:   st,
		version: version,
		started: time.Now(),
		now:     time.Now,
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

	var actualManaged []domain.ManagedRoute
	for _, r := range append(append([]domain.Route{}, v4...), v6...) {
		if r.Owner == domain.OwnerRiftRoute {
			actualManaged = append(actualManaged, domain.ManagedRoute{Route: r, ProfileID: r.Profile})
		}
	}
	managed := len(actualManaged)

	// Live drift: desired (enabled profiles) vs actual managed. Skipped when no
	// profiles exist to avoid resolving the gateway on every state push.
	drift := domain.DriftStatus{}
	if s.store != nil {
		if profs, _ := s.store.ListProfiles(); len(profs) > 0 {
			if dRoutes, dRules, _, derr := s.DesiredFromProfiles(ctx, profs); derr == nil {
				plan := routing.Reconcile(dRoutes, actualManaged, dRules, s.actualManagedRules(ctx), s.Platform())
				for _, op := range plan.Ops {
					switch op.Kind {
					case domain.OpAddRoute, domain.OpAddRule:
						drift.Adds++
					case domain.OpDelRoute, domain.OpDelRule:
						drift.Dels++
					}
				}
				drift.Pending = len(plan.Ops) > 0
			}
		}
	}

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
		AutoApply:         s.autoApply,
		GeneratedAt:       s.now(),
	}, nil
}

// Routes returns the routing table, optionally filtered by family and owner.
// An empty family returns both v4 and v6.
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
		for _, r := range rs {
			if owner != "" && r.Owner != owner {
				continue
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// Rules returns Linux policy rules for a family (empty on macOS).
func (s *Service) Rules(ctx context.Context, family domain.Family) ([]domain.PolicyRule, error) {
	if family == "" {
		family = domain.FamilyV4
	}
	return s.prov.ListRules(ctx, family)
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
		out.Note = "domain resolution not yet supported (M5); enter an IP address"
		return out, nil
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
