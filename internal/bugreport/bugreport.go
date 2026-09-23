// Package bugreport renders a plain-text report of the daemon's state for a
// user to attach to an issue: versions, settings, profiles, routes, doctor
// results, recent activity, and the log tail — with every address, domain,
// name, and path replaced by a stable placeholder (internal/redact). Nothing
// is uploaded; the user reviews the text and decides where it goes.
package bugreport

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Amirhat/riftroute/internal/buildinfo"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/redact"
)

// Limits keep a report readable and paste-able.
const (
	MaxRoutes   = 300
	MaxAudit    = 30
	MaxLogLines = 200
)

// Input is everything a report is made of (gathered by the daemon).
type Input struct {
	Now      time.Time
	State    domain.State
	OS       string
	Profiles []domain.Profile
	Lists    []domain.List
	SplitDNS []domain.SplitDNSRoute
	Routes   []domain.Route
	Doctor   domain.DoctorReport
	Audit    []domain.AuditEvent
	// Pending is the crash-journal size; PendingErr reports unreadable entries.
	Pending    int
	PendingErr string
	Log        string
	LogSource  string
	// Identifying values that don't appear as such in the data above but may
	// in log lines and messages: host names, local user and full names.
	Hosts []string
	Users []string
}

// Header opens every report (also used by clients for their own fallback).
func Header(now time.Time) string {
	return "RiftRoute bug report\n====================\n" +
		"Generated " + now.UTC().Format(time.RFC3339) + " (UTC). REVIEW BEFORE SHARING.\n" +
		"Addresses, domains, names and home paths are replaced with placeholders such as\n" +
		"<ip4-lan-1>, <domain-2> or <profile-1>; one placeholder always stands for the same\n" +
		"value. Times are in UTC. Rule comments and profile descriptions are left out.\n"
}

// NewRedactor seeds a redactor with every sensitive value the input knows.
func NewRedactor(in Input) *redact.Redactor {
	r := redact.New()
	for _, p := range in.Profiles {
		r.Add(redact.Profile, p.Name, p.ID)
		for _, rule := range p.Rules {
			switch rule.Type {
			case domain.RuleDomain:
				r.Add(redact.Domain, rule.Value)
			case domain.RuleApp:
				if !isNumeric(rule.Value) { // a bare uid identifies no one
					r.Add(redact.App, rule.Value)
				}
			case domain.RuleASN, domain.RuleCountry:
				r.Add(redact.Rule, rule.Value)
			}
		}
	}
	for _, l := range in.Lists {
		r.Add(redact.List, l.Name)
		r.Add(redact.URL, l.Source)
		for _, e := range l.Static {
			if strings.ContainsAny(e, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") && !strings.Contains(e, ":") {
				r.Add(redact.Domain, e)
			}
		}
	}
	for _, sd := range in.SplitDNS {
		r.Add(redact.Domain, sd.Domain)
	}
	r.Add(redact.Domain, in.State.DNS.SearchDomains...)
	r.Add(redact.Host, in.Hosts...)
	r.Add(redact.User, in.Users...)
	for _, ifc := range in.State.Interfaces {
		if !GenericIface(ifc.Name) {
			r.Add(redact.Iface, ifc.Name) // e.g. "nordlynx", "wg-mullvad": names a VPN provider
		}
	}
	return r
}

var genericIface = regexp.MustCompile(`^(lo|en|eth|wlan|wlp|wwan|enp|eno|ens|utun|ipsec|ppp|tun|tap|wg|bridge|br|awdl|llw|anpi|ap|gif|stf|docker|veth|virbr|vmnet|vboxnet|p2p|pktap|ham|zt)\d*([a-z]\d+)*$`)

// GenericIface reports whether an interface name is a generic OS/driver name
// (en0, utun4, wlp2s0) rather than one that names a product or provider.
func GenericIface(name string) bool { return genericIface.MatchString(name) }

func isNumeric(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

// Render produces the redacted report text.
func Render(in Input) domain.BugReport {
	r := NewRedactor(in)
	rs := r.String
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	section := func(title string) { line("\n## %s", title) }

	b.WriteString(Header(in.Now))

	h := in.State.Health
	section("Daemon")
	line("build      %s", buildinfo.Short(h.Build))
	if h.Build.Platform != "" || h.Build.GoVersion != "" {
		line("platform   %s · %s", h.Build.Platform, h.Build.GoVersion)
	}
	line("os         %s", rs(in.OS))
	if h.Binary != "" {
		line("binary     %s", rs(h.Binary))
	}
	if !h.StartedAt.IsZero() {
		line("started    %s (up %s)", h.StartedAt.UTC().Format(time.RFC3339), (time.Duration(h.UptimeSeconds) * time.Second).String())
	}
	line("health     %s%s", h.Daemon, optional(" — ", rs(h.Reason)))
	line("provider   %s · backend %s", h.Provider, orDash(in.State.Capabilities.Backend))
	line("schema     %d", h.SchemaVersion)
	if h.RestartRequired {
		line("RESTART    needed: %s", rs(h.RestartReason))
	}

	section("Settings")
	line("auto-apply %s · kill switch %s · updates %s · telemetry %s",
		onOff(in.State.AutoApply), onOff(in.State.KillSwitch), in.State.Preferences.Updates, in.State.Preferences.Telemetry)
	c := in.State.Capabilities
	line("caps       policy-routing=%s per-app=%s kill-switch=%s ipv6=%s", yn(c.PolicyRouting), yn(c.PerAppRouting), yn(c.KillSwitch), yn(c.IPv6))

	section("Network")
	vpn := "inactive"
	if in.State.VPN.Active {
		vpn = "active (" + rs(strings.Join(in.State.VPN.Interfaces, ", ")) + ")"
	}
	line("vpn        %s", vpn)
	for _, d := range in.State.Defaults {
		if !d.Present {
			line("default    %s: none", d.Family)
			continue
		}
		via := "direct"
		if d.ViaVPN {
			via = "via VPN"
		}
		line("default    %s: %s dev %s [%s] %s", d.Family, rs(orDash(d.Gateway)), rs(d.Iface), d.Owner, via)
	}
	line("dns        %s", rs(strings.Join(in.State.DNS.Servers, ", ")))
	dr := in.State.Drift
	if dr.Pending {
		line("drift      pending +%d -%d%s", dr.Adds, dr.Dels, optional(" — ", rs(dr.Reason)))
	} else {
		line("drift      none")
	}
	line("managed    %d route(s), %d rule(s)", in.State.ManagedRouteCount, in.State.ManagedRuleCount)
	var ifs []string
	for _, ifc := range in.State.Interfaces {
		state := "down"
		if ifc.Up {
			state = "up"
		}
		tag := ""
		if ifc.IsVPN {
			tag = ",vpn"
		}
		ifs = append(ifs, fmt.Sprintf("%s(%s%s)", rs(ifc.Name), state, tag))
	}
	line("interfaces %s", strings.Join(ifs, " "))

	section(fmt.Sprintf("Profiles (%d)", len(in.Profiles)))
	for _, p := range in.Profiles {
		line("%s  mode=%s enabled=%s gateway=%s priority=%d lists=%s",
			rs(p.Name), p.Mode, yn(p.Enabled), rs(orDash(p.Gateway)), p.Priority, rs(orDash(strings.Join(p.Lists, ","))))
		for _, rule := range p.Rules {
			line("  %-7s %s", rule.Type, rs(rule.Value))
		}
	}
	if len(in.Lists) > 0 {
		section(fmt.Sprintf("Lists (%d)", len(in.Lists)))
		for _, l := range in.Lists {
			line("%s  entries=%d%s", rs(l.Name), len(l.Entries()), optional(" source=", rs(l.Source)))
		}
	}
	if len(in.SplitDNS) > 0 {
		section("Split DNS")
		for _, sd := range in.SplitDNS {
			line("%s -> %s", rs(sd.Domain), rs(sd.Resolver))
		}
	}

	section(fmt.Sprintf("Doctor (%d pass, %d warn, %d fail)", in.Doctor.Pass, in.Doctor.Warn, in.Doctor.Fail))
	for _, ch := range in.Doctor.Checks {
		line("[%s] %s: %s", ch.Status, ch.Name, rs(ch.Detail))
	}

	routes := append([]domain.Route(nil), in.Routes...)
	sort.SliceStable(routes, func(i, j int) bool { return routes[i].Family < routes[j].Family })
	section(fmt.Sprintf("Routing table (%d)", len(routes)))
	for i, rt := range routes {
		if i == MaxRoutes {
			line("… %d more not shown", len(routes)-MaxRoutes)
			break
		}
		line("%s %s via %s dev %s [%s]%s", rt.Family, rs(rt.DstCIDR), rs(orDash(rt.Gateway)), rs(rt.Iface), rt.Owner, optional(" table ", rt.Table))
	}

	section(fmt.Sprintf("Recent activity (last %d)", min(len(in.Audit), MaxAudit)))
	for i, ev := range in.Audit {
		if i == MaxAudit {
			break
		}
		rb := ""
		if ev.Rollback {
			rb = " rollback"
		}
		line("%s %s %s %s%s%s%s", ev.TS.UTC().Format(time.RFC3339), ev.Actor, ev.Action, ev.Result, rb,
			optional(" profile=", rs(ev.Profile)), optional(" — ", rs(ev.Reason)))
	}

	section("Crash journal")
	line("pending transactions: %d%s", in.Pending, optional(" — ", rs(in.PendingErr)))

	if in.Log == "" {
		section("Daemon log")
		line("(no log file — the daemon is not running as an installed service)")
	} else {
		section(fmt.Sprintf("Daemon log (last %d lines of %s)", MaxLogLines, rs(in.LogSource)))
		lines := strings.Split(strings.TrimRight(in.Log, "\n"), "\n")
		if len(lines) > MaxLogLines {
			lines = lines[len(lines)-MaxLogLines:]
		}
		for _, l := range lines {
			line("%s", rs(l))
		}
	}
	return domain.BugReport{Text: b.String(), Redactions: r.Count(), GeneratedAt: in.Now.UTC()}
}

func optional(prefix, v string) string {
	if strings.TrimSpace(v) == "" {
		return ""
	}
	return prefix + v
}

func orDash(v string) string {
	if v == "" {
		return "-"
	}
	return v
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
