package core

import (
	"context"
	"net/netip"
	"strings"

	"github.com/Amirhat/riftroute/internal/domain"
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

	// Ownership drift (desired vs actual).
	if d, err := s.Diff(ctx); err == nil {
		if d.InSync {
			add("drift", domain.CheckPass, "desired routing matches actual", "")
		} else {
			add("drift", domain.CheckWarn, "reconciliation pending (desired != actual)", "run `riftroute apply` to converge")
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
