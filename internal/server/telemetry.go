package server

// Telemetry (phase 3, docs/telemetry.md): anonymous daily reports in, a
// dashboard and a read-only summary API out. A report is decoded strictly
// (telemetry.Decode: the schema's fields and fixed values only), and what's
// stored is the decoded report encoded again, never the bytes that came in.
// Nothing about the sender is kept: no address, no header; the throttle
// holds keyed hashes in memory for its window only, as for logins.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Amirhat/riftroute/internal/telemetry"
)

// telemetryKeepDays is how long reports are kept.
const telemetryKeepDays = 180

// summaryMaxDays bounds a summary's window.
const summaryMaxDays = 90

// newTelemetryLimiter throttles report uploads: one install sends one a day,
// so 30 an hour from one address covers a large office behind one NAT, and
// 2,000 an hour in all is well past the daily cap's pace.
func newTelemetryLimiter() *limiter { return newLimiter(time.Hour, 30, 2000) }

// What reports may take of the shared host, whoever sends them (vars for
// tests): at most telemetryDailyCap kept a day — a repeat of one already
// kept replaces it, and doesn't count — and none while the database is past
// telemetryMaxDB or the disk below telemetryMinFree. A valid report is
// under 2.5 KiB, so a day at the cap is about 12 MiB.
var (
	telemetryDailyCap        = 5000
	telemetryMaxDB    int64  = 512 << 20
	telemetryMinFree  uint64 = 1 << 30
)

// telemetryRoom says why no new report for day from install may be kept
// now, or "".
func (s *Server) telemetryRoom(day, install string) (string, error) {
	n, has, err := s.st.reportsOn(day, install)
	if err != nil {
		return "", err
	}
	if has {
		return "", nil // replaces its own
	}
	switch {
	case n >= telemetryDailyCap:
		return "the day's cap", nil
	case s.st.size() > telemetryMaxDB:
		return "the database's size cap", nil
	}
	if s.cfg.DiskFree != nil {
		if free, err := s.cfg.DiskFree(s.cfg.DataDir); err == nil && free < telemetryMinFree {
			return "low disk space", nil
		}
	}
	return "", nil
}

func (s *Server) handleTelemetry(w http.ResponseWriter, r *http.Request) {
	now := s.cfg.Now()
	reply := func(status int, msg string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
	}
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		reply(http.StatusUnsupportedMediaType, "a report is JSON")
		return
	}
	if !s.tlim.begin(clientKey(r), false, now) {
		reply(http.StatusTooManyRequests, "too many reports; try again later")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, telemetry.MaxReportBytes))
	if err != nil {
		reply(http.StatusRequestEntityTooLarge, "report too large")
		return
	}
	rep, err := telemetry.Decode(body)
	if err != nil {
		// The error names schema fields only, never the values sent.
		reply(http.StatusBadRequest, err.Error())
		return
	}
	day, _ := time.Parse(time.DateOnly, rep.Day) // Decode checked it
	today := utcDay(now)
	if day.Before(today.AddDate(0, 0, -1)) || day.After(today.AddDate(0, 0, 1)) {
		reply(http.StatusBadRequest, "report: day out of range")
		return
	}
	full, err := s.telemetryRoom(rep.Day, rep.Install)
	if err == nil && full != "" {
		s.tfull.Lock()
		if now.Sub(s.tfullAt) >= time.Hour {
			s.tfullAt = now
			s.cfg.Logger.Warn("telemetry reports refused", "why", full) // at most hourly
		}
		s.tfull.Unlock()
		reply(http.StatusServiceUnavailable, "not taking reports now; try again later")
		return
	}
	if err == nil {
		err = s.st.putReport(rep, now)
	}
	if err != nil {
		s.cfg.Logger.Error("telemetry report not stored", "err", err)
		reply(http.StatusInternalServerError, "not stored; try again later")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// utcDay is t's UTC day at midnight.
func utcDay(t time.Time) time.Time { return t.UTC().Truncate(24 * time.Hour) }

// --- the summary ---

// Summary is what the reports in a window say: the dashboard shows it and
// the summary API returns it.
type Summary struct {
	Days     int    `json:"days"`
	From     string `json:"from"`
	To       string `json:"to"`
	Reports  int    `json:"reports"`
	Installs int    `json:"installs"` // distinct install ids (renewed every 30 days)
	Daily    []Day  `json:"daily"`
	// Versions, newest first.
	Versions  []VersionSummary         `json:"versions"`
	Platforms Platforms                `json:"platforms"`
	Tunnels   map[string]TunnelSummary `json:"tunnels"`
	Usage     UsageSummary             `json:"usage"`
	// Flags are what stands out: a version doing worse than the one before
	// it, rollbacks.
	Flags []Flag `json:"flags"`
}

// Day is one day's reports.
type Day struct {
	Day      string `json:"day"`
	Installs int    `json:"installs"`
	Full     int    `json:"full"`
}

// VersionSummary is one version's reports, summed.
type VersionSummary struct {
	Version  string            `json:"version"`
	Installs int               `json:"installs"`
	Reports  int               `json:"reports"`
	Daemon   telemetry.Daemon  `json:"daemon"`
	Updates  telemetry.Updates `json:"updates"`
	// Applies are from full reports only.
	Applies telemetry.Applies `json:"applies"`
	// Installs with at least one unclean start, recovered panic, or update
	// rolled back for its health.
	InstallsUnclean    int `json:"installs_unclean"`
	InstallsPanicked   int `json:"installs_panicked"`
	InstallsRolledBack int `json:"installs_rolled_back"`
	// Installs with at least one failed change, or failed tunnel attempt.
	InstallsApplyFailed  int `json:"installs_apply_failed"`
	InstallsTunnelFailed int `json:"installs_tunnel_failed"`
	// Rates, each install weighing the same (one with many reports, or a
	// forged one with huge counts, counts once): the share of installs with
	// an unclean start, and the installs' own rates of failed and slow
	// changes and failed tunnel attempts, averaged. Nil when fewer than
	// minInstalls installs say.
	UncleanRate    *float64 `json:"unclean_rate"`
	ApplyFailRate  *float64 `json:"apply_fail_rate"`
	SlowRate       *float64 `json:"slow_rate"`
	TunnelFailRate *float64 `json:"tunnel_fail_rate"`
}

// Platforms count installs (each install's latest report in the window).
type Platforms struct {
	OS      map[string]int `json:"os"` // "darwin 15", "linux 24"
	Arch    map[string]int `json:"arch"`
	Distro  map[string]int `json:"distro"`
	Level   map[string]int `json:"level"`
	Channel map[string]int `json:"channel"`
	Service int            `json:"service"`
}

// TunnelSummary is one protocol's sessions.
type TunnelSummary struct {
	Connected int            `json:"connected"`
	Drops     int            `json:"drops"`
	GaveUp    int            `json:"gave_up"`
	Failed    int            `json:"failed"`
	FailedBy  map[string]int `json:"failed_by"`
	// ConnectRate is the installs' own connected / (connected + failed),
	// averaged (each install weighing the same).
	ConnectRate *float64 `json:"connect_rate"`
}

// UsageSummary counts installs at full (their latest full report) using
// each feature.
type UsageSummary struct {
	Installs     int            `json:"installs"`
	Profiles     int            `json:"profiles"` // summed
	KillSwitch   int            `json:"kill_switch"`
	SplitDNS     int            `json:"split_dns"`
	AutoApply    int            `json:"auto_apply"`
	RemoteLists  int            `json:"remote_lists"`
	ProfileModes map[string]int `json:"profile_modes"`
	RuleKinds    map[string]int `json:"rule_kinds"`
	TunnelTypes  map[string]int `json:"tunnel_types"`
	Refused      map[string]int `json:"refused"`     // applies refused, by rule
	RolledBack   map[string]int `json:"rolled_back"` // changes rolled back, by reason
	ApplyMS      map[string]int `json:"apply_ms"`    // applied changes by duration
}

// Flag is something the owner should look at.
type Flag struct {
	Version string `json:"version,omitempty"`
	What    string `json:"what"`
}

// minInstalls is how many installs a rate needs before it's shown or
// compared; minFlagInstalls, how many must show a panic or a rollback for a
// flag. Install ids are anonymous and self-chosen, so a flag is a hint: what
// these bound is how much one report can move one.
const (
	minInstalls     = 10
	minFlagInstalls = 3
)

func rate(n, of, min int) *float64 {
	if of < min || of == 0 {
		return nil
	}
	r := float64(n) / float64(of)
	return &r
}

// The most one report counts for, whatever it says: what one machine
// plausibly does in a day, or a few missed ones. A report claiming more
// weighs no more (Validate takes anything up to 1,000,000).
const (
	capStarts  = 100
	capPanics  = 100
	capUpdates = 10
	capApplies = 5000
	capTunnel  = 500
)

// clamp is r counted as at most one machine's day (capStarts…).
func clamp(r telemetry.Report) telemetry.Report {
	c := func(n, max int) int { return min(n, max) }
	r.Daemon.Starts = c(r.Daemon.Starts, capStarts)
	r.Daemon.Unclean = c(r.Daemon.Unclean, r.Daemon.Starts)
	r.Daemon.Panics = c(r.Daemon.Panics, capPanics)
	u := &r.Updates
	u.Installed, u.RolledBackHealth, u.RolledBackUser = c(u.Installed, capUpdates), c(u.RolledBackHealth, capUpdates), c(u.RolledBackUser, capUpdates)
	u.SkippedBroken, u.HelpersRepaired, u.CheckFailed = c(u.SkippedBroken, capUpdates), c(u.HelpersRepaired, capUpdates), c(u.CheckFailed, capApplies)
	capMap := func(m map[string]int, max int) map[string]int {
		out := make(map[string]int, len(m))
		for k, n := range m {
			out[k] = c(n, max)
		}
		return out
	}
	if a := r.Applies; a != nil {
		ca := *a
		ca.Applied, ca.Auto, ca.Failed = c(a.Applied, capApplies), c(a.Auto, capApplies), c(a.Failed, capApplies)
		ca.Slow = c(a.Slow, ca.Applied)
		ca.Refused, ca.RolledBack, ca.MS = capMap(a.Refused, capApplies), capMap(a.RolledBack, capApplies), capMap(a.MS, capApplies)
		r.Applies = &ca
	}
	if r.Tunnels != nil {
		ts := make(map[string]telemetry.TunnelSessions, len(r.Tunnels))
		for typ, t := range r.Tunnels {
			t.Connected, t.Drops, t.GaveUp = c(t.Connected, capTunnel), c(t.Drops, capTunnel), c(t.GaveUp, capTunnel)
			t.Failed = capMap(t.Failed, capTunnel)
			ts[typ] = t
		}
		r.Tunnels = ts
	}
	return r
}

// perInstall is what one install's reports in a window add up to.
type perInstall struct {
	starts, unclean, panics, rolledBack int
	applied, failed, slow               int
	tunnelOK, tunnelFailed              int
}

// mean averages per-install rates, nil below minInstalls.
func mean(rates []float64) *float64 {
	if len(rates) < minInstalls {
		return nil
	}
	t := 0.0
	for _, r := range rates {
		t += r
	}
	m := t / float64(len(rates))
	return &m
}

// summarize sums the reports each yields, newest first, for the window
// [from, to]. It keeps per install only its id (the newest report says its
// platform and usage), so a window with many installs costs little memory.
func summarize(each func(fn func(telemetry.Report)) error, from, to time.Time) (Summary, error) {
	days := int(to.Sub(from).Hours()/24) + 1
	sum := Summary{
		Days: days, From: from.Format(time.DateOnly), To: to.Format(time.DateOnly),
		Platforms: Platforms{OS: map[string]int{}, Arch: map[string]int{}, Distro: map[string]int{}, Level: map[string]int{}, Channel: map[string]int{}},
		Tunnels:   map[string]TunnelSummary{},
		Usage: UsageSummary{
			ProfileModes: map[string]int{}, RuleKinds: map[string]int{}, TunnelTypes: map[string]int{},
			Refused: map[string]int{}, RolledBack: map[string]int{}, ApplyMS: map[string]int{},
		},
		Flags: []Flag{},
	}
	for d := from; !d.After(to); d = d.AddDate(0, 0, 1) {
		sum.Daily = append(sum.Daily, Day{Day: d.Format(time.DateOnly)})
	}
	daily := map[string]*Day{}
	for i := range sum.Daily {
		daily[sum.Daily[i].Day] = &sum.Daily[i]
	}
	versions := map[string]*VersionSummary{}
	versionInstalls := map[string]map[string]*perInstall{}
	tunnelInstalls := map[string]map[string]*perInstall{} // by protocol
	seen := map[string]bool{}                             // installs whose newest report was counted
	seenFull := map[string]bool{}                         // …and newest full one
	rolledBack := map[string]bool{}                       // installs that rolled an update back for its health
	err := each(func(r telemetry.Report) {
		r = clamp(r)
		sum.Reports++
		if d := daily[r.Day]; d != nil {
			d.Installs++
			if r.Level == "full" {
				d.Full++
			}
		}
		if !seen[r.Install] {
			seen[r.Install] = true
			p := &sum.Platforms
			system := r.App.OS
			if r.App.OSMajor > 0 {
				system += " " + strconv.Itoa(r.App.OSMajor)
			}
			p.OS[system]++
			p.Arch[r.App.Arch]++
			if r.App.Distro != "" {
				p.Distro[r.App.Distro]++
			}
			p.Level[r.Level]++
			p.Channel[r.App.Channel]++
			if r.App.Service {
				p.Service++
			}
		}
		if u := r.Usage; r.Level == "full" && u != nil && !seenFull[r.Install] {
			seenFull[r.Install] = true
			us := &sum.Usage
			us.Installs++
			us.Profiles += u.Profiles
			us.KillSwitch += b2i(u.KillSwitch)
			us.SplitDNS += b2i(u.SplitDNS)
			us.AutoApply += b2i(u.AutoApply)
			us.RemoteLists += b2i(u.ListsRemote > 0)
			for k, n := range u.ProfileModes {
				us.ProfileModes[k] += b2i(n > 0)
			}
			for k, n := range u.Rules {
				us.RuleKinds[k] += b2i(n > 0)
			}
			for k, n := range u.Tunnels {
				us.TunnelTypes[k] += b2i(n > 0)
			}
		}
		v := versions[r.App.Version]
		if v == nil {
			v = &VersionSummary{Version: r.App.Version, Applies: telemetry.Applies{Refused: map[string]int{}, RolledBack: map[string]int{}, MS: map[string]int{}}}
			versions[r.App.Version] = v
			versionInstalls[r.App.Version] = map[string]*perInstall{}
		}
		pi := versionInstalls[r.App.Version][r.Install]
		if pi == nil {
			pi = &perInstall{}
			versionInstalls[r.App.Version][r.Install] = pi
		}
		pi.starts += r.Daemon.Starts
		pi.unclean += r.Daemon.Unclean
		pi.panics += r.Daemon.Panics
		pi.rolledBack += r.Updates.RolledBackHealth
		if r.Updates.RolledBackHealth > 0 {
			rolledBack[r.Install] = true
		}
		v.Reports++
		v.Daemon.Starts += r.Daemon.Starts
		v.Daemon.Unclean += r.Daemon.Unclean
		v.Daemon.Panics += r.Daemon.Panics
		u := r.Updates
		v.Updates.Installed += u.Installed
		v.Updates.RolledBackHealth += u.RolledBackHealth
		v.Updates.RolledBackUser += u.RolledBackUser
		v.Updates.SkippedBroken += u.SkippedBroken
		v.Updates.HelpersRepaired += u.HelpersRepaired
		v.Updates.CheckFailed += u.CheckFailed
		if a := r.Applies; a != nil {
			pi.applied += a.Applied
			pi.failed += a.Failed
			pi.slow += a.Slow
			v.Applies.Applied += a.Applied
			v.Applies.Auto += a.Auto
			v.Applies.Failed += a.Failed
			v.Applies.Slow += a.Slow
			addAll(v.Applies.Refused, a.Refused)
			addAll(v.Applies.RolledBack, a.RolledBack)
			addAll(v.Applies.MS, a.MS)
			addAll(sum.Usage.Refused, a.Refused)
			addAll(sum.Usage.RolledBack, a.RolledBack)
			addAll(sum.Usage.ApplyMS, a.MS)
		}
		for typ, t := range r.Tunnels {
			ts := sum.Tunnels[typ]
			if ts.FailedBy == nil {
				ts.FailedBy = map[string]int{}
			}
			ts.Connected += t.Connected
			ts.Drops += t.Drops
			ts.GaveUp += t.GaveUp
			if tunnelInstalls[typ] == nil {
				tunnelInstalls[typ] = map[string]*perInstall{}
			}
			tp := tunnelInstalls[typ][r.Install]
			if tp == nil {
				tp = &perInstall{}
				tunnelInstalls[typ][r.Install] = tp
			}
			for code, n := range t.Failed {
				ts.Failed += n
				ts.FailedBy[code] += n
				pi.tunnelFailed += n
				tp.tunnelFailed += n
			}
			pi.tunnelOK += t.Connected
			tp.tunnelOK += t.Connected
			sum.Tunnels[typ] = ts
		}
	})
	if err != nil {
		return Summary{}, err
	}
	sum.Installs = len(seen)
	for typ, ts := range sum.Tunnels {
		var rates []float64
		for _, p := range tunnelInstalls[typ] {
			if n := p.tunnelOK + p.tunnelFailed; n > 0 {
				rates = append(rates, float64(p.tunnelOK)/float64(n))
			}
		}
		ts.ConnectRate = mean(rates)
		sum.Tunnels[typ] = ts
	}
	for name, v := range versions {
		ins := versionInstalls[name]
		v.Installs = len(ins)
		started := 0
		var applyFail, slow, tunnelFail []float64
		for _, p := range ins {
			if p.starts > 0 {
				started++
			}
			v.InstallsUnclean += b2i(p.unclean > 0)
			v.InstallsPanicked += b2i(p.panics > 0)
			v.InstallsRolledBack += b2i(p.rolledBack > 0)
			v.InstallsApplyFailed += b2i(p.failed > 0)
			v.InstallsTunnelFailed += b2i(p.tunnelFailed > 0)
			if n := p.applied + p.failed; n > 0 {
				applyFail = append(applyFail, float64(p.failed)/float64(n))
			}
			if p.applied > 0 {
				slow = append(slow, float64(p.slow)/float64(p.applied))
			}
			if n := p.tunnelOK + p.tunnelFailed; n > 0 {
				tunnelFail = append(tunnelFail, float64(p.tunnelFailed)/float64(n))
			}
		}
		v.UncleanRate = rate(v.InstallsUnclean, started, minInstalls)
		v.ApplyFailRate, v.SlowRate, v.TunnelFailRate = mean(applyFail), mean(slow), mean(tunnelFail)
		sum.Versions = append(sum.Versions, *v)
	}
	sortVersions(sum.Versions)
	sum.Flags = flags(sum.Versions, len(rolledBack))
	for _, d := range sum.Daily {
		if d.Installs >= telemetryDailyCap {
			sum.Flags = append(sum.Flags, Flag{What: fmt.Sprintf("%s reached the daily cap of %d reports: more were refused — a flood, or time to raise the cap", d.Day, telemetryDailyCap)})
		}
	}
	return sum, nil
}

// flags compares each version with the one before it. Rates are install-
// weighted, and a panic or rollback flag needs minFlagInstalls installs.
func flags(vs []VersionSummary, rolledBack int) []Flag {
	out := []Flag{}
	if rolledBack >= minFlagInstalls {
		out = append(out, Flag{What: fmt.Sprintf("%d installs rolled back an update that failed the health check — counted by the version they went back to, so look at the newest release", rolledBack)})
	}
	// Worse: more than twice the rate before, clearly higher, and seen on
	// several installs (one install, real or forged, is one vote).
	worse := func(cur, prev *float64, by float64, installs int) bool {
		return cur != nil && prev != nil && *cur > *prev*2 && *cur-*prev >= by && installs >= minFlagInstalls
	}
	for i := 0; i+1 < len(vs); i++ {
		v, p := vs[i], vs[i+1]
		if v.Version == "dev" || p.Version == "dev" {
			continue
		}
		add := func(what string, cur, prev *float64) {
			out = append(out, Flag{Version: v.Version, What: fmt.Sprintf("%s: %s, against %s on %s", what, pct(cur), pct(prev), p.Version)})
		}
		if worse(v.UncleanRate, p.UncleanRate, 0.05, v.InstallsUnclean) {
			add("more unclean starts", v.UncleanRate, p.UncleanRate)
		}
		if worse(v.ApplyFailRate, p.ApplyFailRate, 0.02, v.InstallsApplyFailed) {
			add("more changes fail", v.ApplyFailRate, p.ApplyFailRate)
		}
		if worse(v.TunnelFailRate, p.TunnelFailRate, 0.10, v.InstallsTunnelFailed) {
			add("more tunnel attempts fail", v.TunnelFailRate, p.TunnelFailRate)
		}
		if v.InstallsPanicked >= minFlagInstalls && p.InstallsPanicked == 0 {
			out = append(out, Flag{Version: v.Version, What: fmt.Sprintf("%d installs recovered from panics; none on %s", v.InstallsPanicked, p.Version)})
		}
	}
	return out
}

// sortVersions orders releases newest first, "dev" last.
func sortVersions(vs []VersionSummary) {
	key := func(v string) [3]int {
		var k [3]int
		for i, part := range strings.SplitN(v, ".", 3) {
			k[i], _ = strconv.Atoi(part)
		}
		if v == "dev" {
			return [3]int{-1, -1, -1}
		}
		return k
	}
	for i := 1; i < len(vs); i++ {
		for j := i; j > 0; j-- {
			a, b := key(vs[j-1].Version), key(vs[j].Version)
			if a[0] > b[0] || a[0] == b[0] && (a[1] > b[1] || a[1] == b[1] && a[2] >= b[2]) {
				break
			}
			vs[j-1], vs[j] = vs[j], vs[j-1]
		}
	}
}

func addAll(dst, src map[string]int) {
	for k, n := range src {
		dst[k] += n
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// pct formats a rate ("—" when there's too little to say).
func pct(r *float64) string {
	if r == nil {
		return "—"
	}
	p := *r * 100
	if p > 0 && p < 1 {
		return fmt.Sprintf("%.1f%%", p)
	}
	return fmt.Sprintf("%.0f%%", p)
}

// summaryTTL is how long a summary is served before it's worked out again
// (the dashboard and the API ask often; reports come once a day).
const summaryTTL = time.Minute

// summary reads and sums the last days days.
func (s *Server) summary(days int) (Summary, error) {
	now := s.cfg.Now()
	s.sumMu.Lock()
	defer s.sumMu.Unlock() // one at a time: a summary of many reports is work
	if c, ok := s.sums[days]; ok && now.Sub(c.at) < summaryTTL && !now.Before(c.at) {
		return c.sum, nil
	}
	to := utcDay(now)
	from := to.AddDate(0, 0, -(days - 1))
	sum, err := summarize(func(fn func(telemetry.Report)) error {
		return s.st.eachReport(from.Format(time.DateOnly), to.Format(time.DateOnly), true, fn)
	}, from, to)
	if err != nil {
		return Summary{}, err
	}
	if s.sums == nil {
		s.sums = map[int]cachedSummary{}
	}
	s.sums[days] = cachedSummary{at: now, sum: sum}
	return sum, nil
}

type cachedSummary struct {
	at  time.Time
	sum Summary
}

// windowDays reads ?days= (default 7, at most summaryMaxDays).
func windowDays(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("days"))
	if err != nil || n < 1 {
		return 7
	}
	return min(n, summaryMaxDays)
}

// --- the summary API's token ---

func telemetryTokenFile(dataDir string) string { return filepath.Join(dataDir, "telemetry-token.hash") }

// NewTelemetryToken creates the summary API's read-only token, replacing
// any earlier one. The token is returned (to be shown once); only its hash
// is kept.
func NewTelemetryToken(dataDir string) (string, error) {
	token := randomToken()
	if err := writeAtomic(telemetryTokenFile(dataDir), []byte(sha256hex(token)+"\n")); err != nil {
		return "", err
	}
	return token, nil
}

// summaryAllowed reports whether r carries the summary API's token.
func (s *Server) summaryAllowed(r *http.Request) bool {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return false
	}
	b, err := os.ReadFile(telemetryTokenFile(s.cfg.DataDir))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.cfg.Logger.Error("can't read the telemetry token file", "err", err)
		}
		return false
	}
	return equalTokens(strings.TrimSpace(string(b)), sha256hex(strings.TrimSpace(token)))
}

func (s *Server) handleTelemetrySummary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !s.summaryAllowed(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="riftroute-telemetry"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"a valid token is needed (riftroute-server telemetry-token)"}` + "\n"))
		return
	}
	sum, err := s.summary(windowDays(r))
	if err != nil {
		s.cfg.Logger.Error("telemetry summary failed", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal error"}` + "\n"))
		return
	}
	_ = json.NewEncoder(w).Encode(sum)
}

// --- the dashboard ---

// Share is one row of a breakdown.
type Share struct {
	Name string
	N    int
	Pct  float64 // of the total, 0–100
}

// shares orders a breakdown by count, largest first, as shares of total.
func shares(m map[string]int, total int) []Share {
	out := make([]Share, 0, len(m))
	for k, n := range m {
		out = append(out, Share{Name: k, N: n, Pct: share(n, total)})
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && (out[j].N > out[j-1].N || out[j].N == out[j-1].N && out[j].Name < out[j-1].Name); j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// sumOf is a breakdown's total.
func sumOf(m map[string]int) int {
	t := 0
	for _, n := range m {
		t += n
	}
	return t
}

func (s *Server) handleTelemetryDashboard(w http.ResponseWriter, r *http.Request) {
	_, csrf, ok := s.sessionFrom(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	days := windowDays(r)
	sum, err := s.summary(days)
	if err != nil {
		s.cfg.Logger.Error("telemetry summary failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	peak := 1
	for _, d := range sum.Daily {
		peak = max(peak, d.Installs)
	}
	u := sum.Usage
	ms := sumOf(u.ApplyMS)
	var durations []Share
	for i, b := range telemetry.DurationBuckets {
		durations = append(durations, Share{Name: durationNames[i], N: u.ApplyMS[b], Pct: share(u.ApplyMS[b], ms)})
	}
	s.render(w, http.StatusOK, "telemetry.html", map[string]any{
		"CSRF": csrf, "S": sum, "Peak": peak, "Windows": []int{7, 30, 90},
		"MinInstalls": minInstalls, "MinFlagInstalls": minFlagInstalls,
		"Durations": durations,
		"Service": []Share{
			{Name: "service", N: sum.Platforms.Service, Pct: share(sum.Platforms.Service, sum.Installs)},
			{Name: "not", N: sum.Installs - sum.Platforms.Service, Pct: share(sum.Installs-sum.Platforms.Service, sum.Installs)},
		},
		"Features": shares(map[string]int{
			"kill switch": u.KillSwitch, "split DNS": u.SplitDNS, "auto-apply": u.AutoApply, "a remote list": u.RemoteLists,
		}, u.Installs),
	})
}

// durationNames label telemetry.DurationBuckets, in order.
var durationNames = []string{"under 250 ms", "under 1 s", "under 5 s", "5 s or more"}

func share(n, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(n) * 100 / float64(total)
}
