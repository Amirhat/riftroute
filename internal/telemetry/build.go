package telemetry

import (
	"strings"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// Inputs are what a report is built from: the daemon's own records, read at
// build time.
type Inputs struct {
	Level   domain.TelemetryLevel
	Install string
	Now     time.Time
	App     App
	// Counts are the counters' snapshot (Counters.Snapshot).
	Counts map[string]int

	// Full only.
	Profiles   []domain.Profile
	Lists      []domain.List
	Tunnels    []domain.TunnelStatus
	KillSwitch bool
	SplitDNS   bool
	AutoApply  bool
	// Audit are the audit events since the last report.
	Audit []domain.AuditEvent
}

// slowMS is when an applied change counts as slow (the daemon logs it too).
const slowMS = 2000

// Build makes the report. Only counts and values from the schema's fixed
// lists go in: names, values, addresses and reasons in the inputs are read
// for their kind, never copied.
func Build(in Inputs) *Report {
	c := in.Counts
	r := &Report{
		Schema: Schema, Install: in.Install, Level: string(in.Level), Day: in.Now.UTC().Format(time.DateOnly),
		App: in.App,
		Daemon: Daemon{
			// Every unclean start is a start (the counters can't say
			// otherwise; a damaged file might).
			Starts: c[KeyStarts], Unclean: min(c[KeyUnclean], c[KeyStarts]), Panics: c[KeyPanics],
		},
		Updates: Updates{
			Installed: c[KeyInstalled], RolledBackHealth: c[KeyRolledBackHlth], RolledBackUser: c[KeyRolledBackUser],
			SkippedBroken: c[KeySkippedBroken], HelpersRepaired: c[KeyHelpersRepaired], CheckFailed: c[KeyCheckFailed],
		},
	}
	if in.Level != domain.TelemetryFull {
		return r
	}
	r.Usage = usage(in)
	r.Applies, r.Events = applies(in.Audit)
	r.Events.DNSFailures = c[KeyDNSFailures]
	for _, typ := range TunnelTypes {
		s := TunnelSessions{
			Connected: c[TunnelKey(typ, TunnelConnected)], Drops: c[TunnelKey(typ, TunnelDrop)],
			GaveUp: c[TunnelKey(typ, TunnelGaveUp)], Failed: map[string]int{},
		}
		for _, code := range FailureCodes {
			if n := c[FailureKey(typ, code)]; n > 0 {
				s.Failed[code] = n
			}
		}
		if s.Connected+s.Drops+s.GaveUp+len(s.Failed) > 0 {
			if r.Tunnels == nil {
				r.Tunnels = map[string]TunnelSessions{}
			}
			r.Tunnels[typ] = s
		}
	}
	return r
}

func usage(in Inputs) *Usage {
	u := &Usage{
		Profiles: len(in.Profiles), ProfileModes: map[string]int{}, Rules: map[string]int{},
		Lists: len(in.Lists), Tunnels: map[string]int{},
		KillSwitch: in.KillSwitch, SplitDNS: in.SplitDNS, AutoApply: in.AutoApply,
	}
	for _, p := range in.Profiles {
		if p.Enabled {
			u.ProfilesEnabled++
		}
		if m := Known(RuleModes, string(p.Mode)); m != "" {
			u.ProfileModes[m]++
		}
		for _, rule := range p.Rules {
			kind := string(rule.Type)
			if rule.Type == domain.RuleDomain && strings.HasPrefix(rule.Value, "*.") {
				kind = "wildcard"
			}
			if k := Known(RuleKinds, kind); k != "" {
				u.Rules[k]++
			}
		}
	}
	for _, l := range in.Lists {
		if l.Source != "" {
			u.ListsRemote++
		}
	}
	for _, t := range in.Tunnels {
		typ := string(t.Type)
		if typ == "" {
			typ = string(domain.TunnelOpenVPN) // definitions from before types
		}
		if k := Known(TunnelTypes, typ); k != "" {
			u.Tunnels[k]++
		}
		if t.WhenDown == domain.TunnelBlock {
			u.TunnelsBlock++
		}
		if t.Via == domain.TunnelViaDirect || t.Via == "" {
			u.TunnelsDirect++
		}
	}
	return u
}

// applies counts the audit's changes: what was applied (and how fast), what
// failed, was refused (by rule) or rolled back (by reason), and the kill
// switch turning itself off.
func applies(audit []domain.AuditEvent) (*Applies, *Events) {
	a := &Applies{Refused: map[string]int{}, RolledBack: map[string]int{}, MS: map[string]int{}}
	e := &Events{}
	for _, ev := range audit {
		switch {
		case ev.Result == "applied":
			a.Applied++
			if ev.Actor == domain.ActorDaemon {
				a.Auto++
			}
			if t := ev.Timing; t != nil {
				a.MS[DurationBucket(time.Duration(t.TotalMS)*time.Millisecond)]++
				if t.TotalMS >= slowMS {
					a.Slow++
				}
			}
		case ev.Result == "failed" && (ev.Action == "apply" || ev.Action == "route-op"):
			a.Failed++
		case ev.Result == "refused":
			for _, code := range codesOr(ev.Codes) {
				a.Refused[Known(GuardrailRules, code)]++
			}
		case ev.Result == "rolled_back":
			for _, code := range codesOr(ev.Codes) {
				a.RolledBack[Known(RollbackReasons, code)]++
			}
		case ev.Action == "killswitch" && ev.Result == "disabled" && ev.Actor == domain.ActorDaemon:
			e.KillSwitchSafeMode++
		}
	}
	return a, e
}

// codesOr is an event's codes, or "other" for one from before codes.
func codesOr(codes []string) []string {
	if len(codes) == 0 {
		return []string{"other"}
	}
	return codes
}
