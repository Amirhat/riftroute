package domain

import "time"

// DaemonStatus is the daemon's self-reported health.
type DaemonStatus string

const (
	DaemonOK       DaemonStatus = "ok"
	DaemonDegraded DaemonStatus = "degraded"
)

// Health is the daemon's health and identity, surfaced in `status` and the
// dashboard (and designed to paste into bug reports — spec §16).
type Health struct {
	Daemon        DaemonStatus `json:"daemon"`
	Reason        string       `json:"reason,omitempty"`
	Version       string       `json:"version"`
	Provider      string       `json:"provider"` // "fake" | "macos" | "linux" | "unsupported"
	UptimeSeconds int64        `json:"uptime_seconds"`
	PID           int          `json:"pid"`
}

// VPNStatus summarizes detected tunnels.
type VPNStatus struct {
	Active     bool     `json:"active"`
	Interfaces []string `json:"interfaces"`
}

// ProfileStatus is a profile summary for the aggregate state view.
type ProfileStatus struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Mode      Mode   `json:"mode"`
	RuleCount int    `json:"rule_count"`
	// Applied indicates the profile's routes are currently installed.
	Applied bool `json:"applied"`
}

// DriftStatus indicates whether reconciliation is pending (desired != actual).
type DriftStatus struct {
	Pending bool `json:"pending"`
	Adds    int  `json:"adds"`
	Dels    int  `json:"dels"`
	// Reason is set when the desired state itself cannot be computed (e.g. an
	// include profile with no live tunnel). Pending is true in that case: the
	// dashboard must show attention-needed, never a false "in sync", while the
	// installed rules keep fail-safing (include traffic blackholes rather than
	// leaking to the physical path).
	Reason string `json:"reason,omitempty"`
}

// State is the aggregate returned by GET /state — the single source the UI and
// CLI render (spec §11). It is intentionally a flat snapshot so a client can
// render the dashboard from one read.
type State struct {
	Health            Health          `json:"health"`
	Capabilities      Capabilities    `json:"capabilities"`
	VPN               VPNStatus       `json:"vpn"`
	Interfaces        []Iface         `json:"interfaces"`
	Defaults          []DefaultRoute  `json:"defaults"`
	DNS               DNSState        `json:"dns"`
	Profiles          []ProfileStatus `json:"profiles"`
	Drift             DriftStatus     `json:"drift"`
	ManagedRouteCount int             `json:"managed_route_count"`
	// ManagedRuleCount counts owned policy rules (Linux ip rules / macOS PF
	// route-to rules) — the other half of "what RiftRoute installed", so a
	// per-app-only profile doesn't read as "0 managed".
	ManagedRuleCount int `json:"managed_rule_count"`
	// AutoApply reports whether the daemon reconciles automatically on network
	// changes (spec §6 v1 / §10 settings.auto_apply_on_change).
	AutoApply bool `json:"auto_apply"`
	// KillSwitch reports whether egress is currently fenced to the tunnel.
	KillSwitch  bool      `json:"kill_switch"`
	GeneratedAt time.Time `json:"generated_at"`
}
