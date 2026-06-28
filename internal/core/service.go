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
	"github.com/Amirhat/riftroute/internal/store"
)

func pid() int { return os.Getpid() }

// Service is the headless application core.
type Service struct {
	prov    provider.RouteProvider
	store   *store.Store
	version string
	started time.Time
	now     func() time.Time
}

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

	managed := 0
	for _, r := range append(append([]domain.Route{}, v4...), v6...) {
		if r.Owner == domain.OwnerRiftRoute {
			managed++
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
		Drift:             domain.DriftStatus{}, // reconciler-driven (M2+)
		ManagedRouteCount: managed,
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

// Explain answers "where does traffic to target go?". In M0 it returns the
// kernel's decision; the simulated decision + drift detection arrive with the
// routing engine (M1+). Domain targets are not yet resolved (M5).
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
	return out, nil
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
		if r.DstCIDR == defCIDR {
			return domain.DefaultRoute{
				Family: fam, Present: true, Gateway: r.Gateway, Iface: r.Iface,
				Owner: r.Owner, ViaVPN: vpnByIface[r.Iface],
			}
		}
	}
	return domain.DefaultRoute{Family: fam, Present: false, Owner: domain.OwnerUnknown}
}
