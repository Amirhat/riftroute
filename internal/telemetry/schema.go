// Package telemetry is RiftRoute's anonymous usage report (docs/telemetry.md):
// its schema, shared by the daemon that builds it and the server that takes
// it. A report holds only numbers, booleans and values from the fixed lists
// below — never an address, a name, a path or free text — and Validate (run
// by both ends) refuses anything else.
package telemetry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"time"
)

// Schema is the report format's version.
const Schema = 1

// MaxReportBytes bounds a report on the wire.
const MaxReportBytes = 16 << 10

// maxCount caps any one count: a report covers a day (or a few missed ones).
const maxCount = 1_000_000

// Report is one day's report.
type Report struct {
	Schema int `json:"schema"`
	// Install is random, and replaced every 30 days.
	Install string `json:"install"`
	// Level is the level it was built at: full or basic.
	Level string `json:"level"`
	// Day is the UTC day (YYYY-MM-DD) the counts end on.
	Day     string  `json:"day"`
	App     App     `json:"app"`
	Daemon  Daemon  `json:"daemon"`
	Updates Updates `json:"updates"`

	// Full only.
	Usage   *Usage                    `json:"usage,omitempty"`
	Applies *Applies                  `json:"applies,omitempty"`
	Tunnels map[string]TunnelSessions `json:"tunnel_sessions,omitempty"`
	Events  *Events                   `json:"events,omitempty"`
}

// App is what's running, where.
type App struct {
	Version string `json:"version"`
	Channel string `json:"channel"`
	OS      string `json:"os"`
	// OSMajor is the OS's major version (macOS 15; a Linux distribution's
	// VERSION_ID's first number), 0 when unknown.
	OSMajor int `json:"os_major"`
	// Distro is a Linux distribution's ID, from Distros ("other" when not
	// listed); empty elsewhere.
	Distro string `json:"distro,omitempty"`
	Arch   string `json:"arch"`
	// Service: the daemon runs as the installed system service.
	Service bool `json:"service"`
}

// Daemon counts starts.
type Daemon struct {
	Starts int `json:"starts"`
	// Unclean are starts after the daemon didn't stop cleanly (it crashed
	// or was killed).
	Unclean int `json:"unclean"`
	// Panics recovered inside the daemon.
	Panics int `json:"panics,omitempty"`
}

// Updates counts update outcomes.
type Updates struct {
	Installed        int `json:"installed"`
	RolledBackHealth int `json:"rolled_back_health"`
	RolledBackUser   int `json:"rolled_back_user"`
	SkippedBroken    int `json:"skipped_broken"`
	HelpersRepaired  int `json:"helpers_repaired"`
	CheckFailed      int `json:"check_failed"`
}

// Usage is what's configured, counted.
type Usage struct {
	Profiles        int `json:"profiles"`
	ProfilesEnabled int `json:"profiles_enabled"`
	// By mode (RuleModes keys: exclude, include, tunnel).
	ProfileModes map[string]int `json:"profile_modes"`
	// Rules by kind (RuleKinds).
	Rules       map[string]int `json:"rules"`
	Lists       int            `json:"lists"`
	ListsRemote int            `json:"lists_remote"`
	// Tunnels by type (TunnelTypes).
	Tunnels       map[string]int `json:"tunnels"`
	TunnelsBlock  int            `json:"tunnels_block"`
	TunnelsDirect int            `json:"tunnels_direct"`
	KillSwitch    bool           `json:"kill_switch"`
	SplitDNS      bool           `json:"split_dns"`
	AutoApply     bool           `json:"auto_apply"`
}

// Applies counts changes through the Apply Protocol.
type Applies struct {
	Applied int `json:"applied"`
	// Auto are applied ones the daemon made by itself (auto-apply,
	// tunnels).
	Auto   int `json:"auto"`
	Failed int `json:"failed"`
	// Refused by guardrail rule (GuardrailRules).
	Refused map[string]int `json:"refused"`
	// RolledBack by reason (RollbackReasons).
	RolledBack map[string]int `json:"rolled_back"`
	// Slow took over 2 seconds.
	Slow int `json:"slow"`
	// MS buckets an applied change's duration (DurationBuckets).
	MS map[string]int `json:"ms"`
}

// TunnelSessions counts one tunnel type's sessions.
type TunnelSessions struct {
	Connected int `json:"connected"`
	Drops     int `json:"drops"`
	GaveUp    int `json:"gave_up"`
	// Failed attempts by cause (FailureCodes).
	Failed map[string]int `json:"failed"`
}

// Events counts what else happened.
type Events struct {
	// KillSwitchSafeMode: the kill switch turned itself off to keep another
	// VPN working.
	KillSwitchSafeMode int `json:"killswitch_safe_mode"`
	DNSFailures        int `json:"dns_failures"`
}

// The fixed lists every enumerated value comes from.
var (
	Levels   = []string{"full", "basic"}
	OSes     = []string{"darwin", "linux", "other"}
	Arches   = []string{"amd64", "arm64", "other"}
	Channels = []string{"stable", "beta", "other"}
	// Distros are Linux os-release IDs reported as themselves.
	Distros = []string{
		"debian", "ubuntu", "linuxmint", "pop", "elementary", "fedora", "rhel", "rocky", "almalinux", "centos",
		"arch", "manjaro", "endeavouros", "opensuse-leap", "opensuse-tumbleweed", "sles", "alpine", "void",
		"gentoo", "nixos", "other",
	}
	RuleModes       = []string{"exclude", "include", "tunnel"}
	RuleKinds       = []string{"cidr", "ip", "domain", "wildcard", "asn", "country", "app"}
	TunnelTypes     = []string{"openvpn", "wireguard", "ikev2"}
	GuardrailRules  = []string{"gateway-unresolved", "gateway-capture", "bad-gateway", "unreachable-next-hop", "next-hop-via-vpn", "conflicting-route", "ssh-peer", "keep-default-route", "other"}
	RollbackReasons = []string{"watchdog", "unconfirmed", "requested", "shutdown", "other"}
	DurationBuckets = []string{"lt250", "lt1000", "lt5000", "ge5000"}
	// FailureCodes are why a tunnel attempt failed, as its diagnosis says.
	FailureCodes = []string{
		"auth", "proposal", "identity", "cert", "unreachable", "plugin", "handshake", "tls", "eku",
		"web_login", "no_address", "addressing", "engine", "other",
	}
)

// DurationBucket names the bucket a duration falls in.
func DurationBucket(d time.Duration) string {
	switch {
	case d < 250*time.Millisecond:
		return "lt250"
	case d < time.Second:
		return "lt1000"
	case d < 5*time.Second:
		return "lt5000"
	}
	return "ge5000"
}

// Known returns v if it's in list, and "other" if list has an "other" (or
// "" if it doesn't).
func Known(list []string, v string) string {
	if slices.Contains(list, v) {
		return v
	}
	if slices.Contains(list, "other") {
		return "other"
	}
	return ""
}

var (
	reInstall = regexp.MustCompile(`^[0-9a-f]{32}$`)
	reVersion = regexp.MustCompile(`^(\d{1,4}\.\d{1,4}\.\d{1,4}|dev)$`)
)

// Validate checks every field against the schema: the format, the fixed
// lists, and the counts' range. Both the daemon (before sending) and the
// server (before storing) run it.
func (r *Report) Validate() error {
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	if r.Schema != Schema {
		bad("schema %d", r.Schema)
	}
	if !reInstall.MatchString(r.Install) {
		bad("install id")
	}
	if !slices.Contains(Levels, r.Level) {
		bad("level")
	}
	if _, err := time.Parse(time.DateOnly, r.Day); err != nil {
		bad("day")
	}
	a := r.App
	if !reVersion.MatchString(a.Version) {
		bad("app.version")
	}
	for f, v := range map[string][2]any{
		"app.channel": {Channels, a.Channel}, "app.os": {OSes, a.OS}, "app.arch": {Arches, a.Arch},
	} {
		if !slices.Contains(v[0].([]string), v[1].(string)) {
			bad("%s", f)
		}
	}
	if a.Distro != "" && (a.OS != "linux" || !slices.Contains(Distros, a.Distro)) {
		bad("app.distro")
	}
	if a.OSMajor < 0 || a.OSMajor > 1000 {
		bad("app.os_major")
	}
	counts := func(f string, ns ...int) {
		for _, n := range ns {
			if n < 0 || n > maxCount {
				bad("%s out of range", f)
				return
			}
		}
	}
	keyed := func(f string, list []string, m map[string]int) {
		for k, n := range m {
			if !slices.Contains(list, k) {
				bad("%s key", f)
				return
			}
			counts(f, n)
		}
	}
	counts("daemon", r.Daemon.Starts, r.Daemon.Unclean, r.Daemon.Panics)
	u := r.Updates
	counts("updates", u.Installed, u.RolledBackHealth, u.RolledBackUser, u.SkippedBroken, u.HelpersRepaired, u.CheckFailed)

	full := r.Usage != nil || r.Applies != nil || r.Tunnels != nil || r.Events != nil
	if full && r.Level != "full" {
		bad("full fields at level %s", r.Level)
	}
	if us := r.Usage; us != nil {
		counts("usage", us.Profiles, us.ProfilesEnabled, us.Lists, us.ListsRemote, us.TunnelsBlock, us.TunnelsDirect)
		keyed("usage.profile_modes", RuleModes, us.ProfileModes)
		keyed("usage.rules", RuleKinds, us.Rules)
		keyed("usage.tunnels", TunnelTypes, us.Tunnels)
	}
	if ap := r.Applies; ap != nil {
		counts("applies", ap.Applied, ap.Auto, ap.Failed, ap.Slow)
		keyed("applies.refused", GuardrailRules, ap.Refused)
		keyed("applies.rolled_back", RollbackReasons, ap.RolledBack)
		keyed("applies.ms", DurationBuckets, ap.MS)
	}
	for t, s := range r.Tunnels {
		if !slices.Contains(TunnelTypes, t) {
			bad("tunnel_sessions key")
			continue
		}
		counts("tunnel_sessions", s.Connected, s.Drops, s.GaveUp)
		keyed("tunnel_sessions.failed", FailureCodes, s.Failed)
	}
	if e := r.Events; e != nil {
		counts("events", e.KillSwitchSafeMode, e.DNSFailures)
	}
	return errors.Join(errs...)
}

// Decode reads a report strictly: at most MaxReportBytes, one JSON object,
// no field the schema doesn't have, and every value valid.
func Decode(b []byte) (*Report, error) {
	if len(b) > MaxReportBytes {
		return nil, errors.New("report too large")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var r Report
	if err := d.Decode(&r); err != nil {
		return nil, fmt.Errorf("report: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("report: trailing data")
	}
	if err := r.Validate(); err != nil {
		return nil, fmt.Errorf("report: %w", err)
	}
	return &r, nil
}
