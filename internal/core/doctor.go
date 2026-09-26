package core

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/routing"
)

// Doctor runs the diagnostics battery (spec §7.9): a readable pass/warn/fail
// report with suggested fixes — a "network self-test". All checks are reads.
func (s *Service) Doctor(ctx context.Context) domain.DoctorReport {
	r := domain.DoctorReport{GeneratedAt: s.now()}
	add := func(name string, status domain.CheckStatus, detail, fix string) {
		r.Checks = append(r.Checks, domain.DoctorCheck{Name: name, Status: status, Detail: detail, Fix: fix})
	}

	// Daemon / provider.
	add("daemon", domain.CheckPass, "riftrouted is responding (provider "+s.prov.Name()+")", "")

	// Physical gateway resolution (spec §4.4).
	if gw, ifn, err := s.prov.DefaultGateway(ctx, domain.FamilyV4); err == nil && gw.IsValid() {
		add("gateway", domain.CheckPass, "physical gateway "+gw.String()+" via "+ifn, "")
	} else {
		add("gateway", domain.CheckFail, "no physical gateway resolved", "check that a network interface is up with a DHCP/static gateway")
	}

	// Default route present.
	v4, _ := s.prov.ListRoutes(ctx, domain.FamilyV4)
	if def := findDefault(v4, "0.0.0.0/0"); def != "" {
		add("default-route", domain.CheckPass, "v4 default: "+def, "")
	} else {
		add("default-route", domain.CheckFail, "no IPv4 default route", "you may have no internet path")
	}

	// DNS configured.
	if dns, err := s.prov.DNSConfig(ctx); err == nil && len(dns.Servers) > 0 {
		add("dns", domain.CheckPass, "resolvers: "+joinShort(dns.Servers), "")
	} else {
		add("dns", domain.CheckWarn, "no DNS resolvers detected", "check your network's DNS configuration")
	}

	// Ownership drift (desired vs actual) — same computation as State/dashboard.
	if dr := s.computeDrift(ctx, s.actualManagedRoutes(ctx)); dr.Pending {
		add("drift", domain.CheckWarn, "reconciliation pending (desired != actual)", "run `riftroute apply` to converge")
	} else {
		add("drift", domain.CheckPass, "desired routing matches actual", "")
	}

	// Tunnels RiftRoute runs itself.
	if ts := s.TunnelStatuses(ctx); len(ts) > 0 {
		if s.tunnelEngine != nil {
			if e := s.tunnelEngine(); !e.Available {
				fix := "tunnels can't connect until this is fixed"
				if h := e.Install.Summary(); h != "" {
					fix = "on " + e.Install.System + ", " + h
				}
				add("tunnel-engine", domain.CheckFail, e.Problem, fix)
			} else {
				add("tunnel-engine", domain.CheckPass, strings.TrimSpace("OpenVPN "+e.Version+" at "+e.Path), "")
			}
		}
		expected, installed := s.tunnelRoutesInstalled(ctx)
		for _, t := range ts {
			name := "tunnel:" + t.Name
			switch {
			case t.State == domain.TunnelFailed:
				add(name, domain.CheckFail, t.LastError, "fix the login or profile, then `riftroute tunnel up "+t.Name+"`")
			case t.State == domain.TunnelConnected:
				status, detail, fix := connectedTunnelCheck(t, expected[t.Name], installed)
				add(name, status, detail, fix)
			case len(t.Blocked) > 0:
				add(name, domain.CheckWarn, "not installed on this network: "+blockedList(t.Blocked),
					"narrow those routes, or ignore this while on this network")
			default:
				add(name, domain.CheckPass, string(t.State), "")
			}
		}
	}

	// Wildcard DNS learner: with *.domain rules configured, subdomain routing
	// depends on the loopback forwarder being up.
	if n := s.wildcardRuleCount(); n > 0 {
		if s.wildcardStatus != nil {
			if active, port := s.wildcardStatus(); active {
				add("wildcard-dns", domain.CheckPass,
					fmt.Sprintf("learning subdomains for %d wildcard rule(s) via 127.0.0.1:%d", n, port), "")
			} else {
				add("wildcard-dns", domain.CheckWarn,
					"wildcard rules configured but the DNS learner is not active — only the apex domains are routed",
					"restart the daemon; if this persists, per-domain DNS routing is unavailable on this system")
			}
		}
	}

	// MTU / blackhole: a tunnel with a notably low MTU can silently drop large
	// packets; suggest an MSS clamp (spec §7.10).
	if ifaces, err := s.prov.Interfaces(ctx); err == nil {
		for _, ifc := range ifaces {
			if ifc.IsVPN && ifc.Up && ifc.MTU > 0 && ifc.MTU < 1400 {
				mss := ifc.MTU - 40
				add("mtu:"+ifc.Name, domain.CheckWarn,
					fmt.Sprintf("tunnel %s MTU is %d — large packets may blackhole", ifc.Name, ifc.MTU),
					fmt.Sprintf("clamp TCP MSS to %d (nft/pf MSS clamp) on the tunnel path", mss))
			}
		}
	}

	// Managed next-hops reachable + conflicts.
	if cs, err := s.Conflicts(ctx); err == nil && len(cs) > 0 {
		add("conflicts", domain.CheckWarn, "overlapping routes with different next hops", "run `riftroute table show --conflicts`")
	} else {
		add("conflicts", domain.CheckPass, "no route conflicts", "")
	}

	// Leaks fold into the report.
	for _, lk := range s.Leaks(ctx) {
		status := domain.CheckWarn
		if lk.Severity == "fail" {
			status = domain.CheckFail
		}
		add("leak:"+lk.Kind, status, lk.Detail, "review the leak detector")
	}

	for _, c := range r.Checks {
		switch c.Status {
		case domain.CheckPass:
			r.Pass++
		case domain.CheckWarn:
			r.Warn++
		case domain.CheckFail:
			r.Fail++
		}
	}
	r.OK = r.Fail == 0
	return r
}

// tunnelRoutesInstalled returns each tunnel's routes as a tunnel apply would
// install them now (by tunnel name), and the kernel's table to check them
// against.
func (s *Service) tunnelRoutesInstalled(ctx context.Context) (map[string][]domain.ManagedRoute, routing.Installed) {
	expected := map[string][]domain.ManagedRoute{}
	if desired, _, _, err := s.DesiredTunnelsOnly(ctx, s.actualManagedRoutes(ctx)); err == nil {
		for _, d := range desired {
			if name, ok := strings.CutPrefix(d.ProfileID, routing.TunnelProfilePrefix); ok {
				expected[name] = append(expected[name], d)
			}
		}
	}
	var kernel []domain.Route
	for _, fam := range []domain.Family{domain.FamilyV4, domain.FamilyV6} {
		rs, _ := s.prov.ListRoutes(ctx, fam)
		kernel = append(kernel, rs...)
	}
	return expected, routing.IndexInstalled(kernel)
}

// connectedTunnelCheck judges a connected tunnel by what the kernel holds:
// no interface means nothing of it is installed; routes missing from the
// table (an apply refused or still retrying, routes gone with a re-created
// tun) or left out on this network are reported; the count is what really
// goes through it.
func connectedTunnelCheck(t domain.TunnelStatus, expected []domain.ManagedRoute, installed routing.Installed) (domain.CheckStatus, string, string) {
	if t.Iface == "" {
		return domain.CheckFail, "connected, but RiftRoute found no interface for it — none of its routes are installed",
			"reconnect it: `riftroute tunnel down " + t.Name + "`, then `riftroute tunnel up " + t.Name + "`"
	}
	through := 0
	var missing []string
	for _, r := range expected {
		switch {
		case !installed.Has(r.Route) && r.Gateway != "":
			missing = append(missing, r.DstCIDR+" (its server's pin)")
		case !installed.Has(r.Route):
			missing = append(missing, r.DstCIDR)
		case r.Gateway == "":
			through++
		}
	}
	status, detail := domain.CheckPass, fmt.Sprintf("connected on %s; %d route(s) through it", t.Iface, through)
	var fixes []string
	if len(missing) > 0 {
		status = domain.CheckWarn
		detail += "; missing from the routing table: " + strings.Join(missing, ", ")
		fixes = append(fixes, "RiftRoute re-adds them when it next applies; if they stay missing, confirm or roll back any change awaiting confirmation, then reconnect the tunnel")
	}
	if len(t.Blocked) > 0 {
		status = domain.CheckWarn
		detail += "; not installed on this network: " + blockedList(t.Blocked)
		fixes = append(fixes, "narrow the routes left out, or ignore them while on this network")
	}
	if len(t.Captured) > 0 {
		status = domain.CheckWarn
		detail += "; some traffic to it goes elsewhere: " + blockedList(t.Captured)
		fixes = append(fixes, "use destination rules instead of app rules in the include profile, or disable it while the tunnel is up")
	}
	return status, detail, strings.Join(fixes, "; ")
}

func blockedList(bs []domain.TunnelBlocked) string {
	var out []string
	for _, b := range bs {
		out = append(out, b.Route+" ("+b.Reason+")")
	}
	return strings.Join(out, "; ")
}

// Leaks detects IPv6 and DNS leaks against the current state (spec §7.6).
func (s *Service) Leaks(ctx context.Context) []domain.Leak {
	var out []domain.Leak

	ifaces, _ := s.prov.Interfaces(ctx)
	vpnByIface := map[string]bool{}
	vpnActive := false
	for _, ifc := range ifaces {
		vpnByIface[ifc.Name] = ifc.IsVPN
		if ifc.IsVPN && ifc.Up {
			vpnActive = true
		}
	}
	if !vpnActive {
		return out // nothing to leak around when no tunnel is up
	}

	v4, _ := s.prov.ListRoutes(ctx, domain.FamilyV4)
	v6, _ := s.prov.ListRoutes(ctx, domain.FamilyV6)
	v4ViaVPN := defaultViaVPN(v4, "0.0.0.0/0", vpnByIface)
	v6Def := findDefault(v6, "::/0")
	v6ViaVPN := defaultViaVPN(v6, "::/0", vpnByIface)

	// IPv6 leak: v4 goes through the tunnel but v6 has a default that does NOT.
	if v4ViaVPN && v6Def != "" && !v6ViaVPN {
		out = append(out, domain.Leak{
			Kind:     "ipv6",
			Severity: "fail",
			Detail:   "IPv6 default route bypasses the VPN while IPv4 is tunneled (" + v6Def + ")",
		})
	}
	// IPv6 leak (no v6 management): v4 tunneled, v6 present and unmanaged.
	if v4ViaVPN && v6Def == "" {
		// no v6 default at all — fine (no v6 internet to leak).
		_ = v6Def
	}

	// DNS leak: resolver not reachable via a VPN interface while tunneled.
	if v4ViaVPN {
		if dns, err := s.prov.DNSConfig(ctx); err == nil {
			for _, server := range dns.Servers {
				if a, perr := netip.ParseAddr(server); perr == nil {
					if dec, lerr := s.prov.LookupRoute(ctx, a); lerr == nil && dec.Reachable && !vpnByIface[dec.Iface] {
						out = append(out, domain.Leak{
							Kind:     "dns",
							Severity: "warn",
							Detail:   "DNS server " + server + " is reached directly (" + dec.Iface + "), bypassing the tunnel",
						})
					}
				}
			}
		}
	}
	return out
}

func findDefault(routes []domain.Route, def string) string {
	for _, r := range routes {
		if r.Table == "" && r.DstCIDR == def {
			gw := r.Gateway
			if gw == "" {
				gw = "on-link"
			}
			return gw + " dev " + r.Iface
		}
	}
	return ""
}

func defaultViaVPN(routes []domain.Route, def string, vpnByIface map[string]bool) bool {
	for _, r := range routes {
		if r.Table == "" && r.DstCIDR == def {
			return vpnByIface[r.Iface]
		}
	}
	return false
}

func joinShort(ss []string) string {
	if len(ss) <= 3 {
		return strings.Join(ss, ", ")
	}
	return strings.Join(ss[:3], ", ") + " …"
}
