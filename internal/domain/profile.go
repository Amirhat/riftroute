package domain

import "time"

// Mode is a profile's routing mode (spec §5.3).
type Mode string

const (
	// ModeExclude: everything goes through the VPN; the profile's destinations
	// bypass it via the physical gateway. Default.
	ModeExclude Mode = "exclude"
	// ModeInclude: nothing goes through the tunnel by default; only the
	// profile's destinations are routed into it (Linux Model B).
	ModeInclude Mode = "include"
)

// RuleType is the kind of a profile rule (spec §5.1).
type RuleType string

const (
	RuleCIDR    RuleType = "cidr"
	RuleIP      RuleType = "ip"
	RuleDomain  RuleType = "domain"
	RuleASN     RuleType = "asn"
	RuleCountry RuleType = "country"
	RuleApp     RuleType = "app" // Linux only
)

// Rule is one destination matcher inside a profile or list.
type Rule struct {
	Type    RuleType `json:"type"`
	Value   string   `json:"value"`
	Comment string   `json:"comment,omitempty"`
}

// Profile is the unit a user toggles (spec §5.1).
type Profile struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Enabled   bool     `json:"enabled"`
	Mode      Mode     `json:"mode"`
	Gateway   string   `json:"gateway"` // "auto" or an explicit IP
	Priority  int      `json:"priority"`
	Rules     []Rule   `json:"rules"`
	Lists     []string `json:"lists"`
	IPVersion []Family `json:"ip_version,omitempty"`
}

// List is a named, reusable set of rules; static (inline) or remote (spec §5.1).
type List struct {
	Name        string     `json:"name"`
	Static      []string   `json:"static,omitempty"`
	Source      string     `json:"source,omitempty"`  // remote URL (https only)
	Refresh     string     `json:"refresh,omitempty"` // duration string, e.g. "24h"
	LastFetched *time.Time `json:"last_fetched,omitempty"`
	Checksum    string     `json:"checksum,omitempty"`
	// Resolved is the cached set of CIDR/IP entries fetched from a remote source.
	Resolved []string `json:"resolved,omitempty"`
}

// Entries returns the list's effective CIDR/IP entries: inline static plus the
// last-fetched remote cache.
func (l List) Entries() []string {
	out := make([]string, 0, len(l.Static)+len(l.Resolved))
	out = append(out, l.Static...)
	out = append(out, l.Resolved...)
	return out
}

// SplitDNSRoute selects a resolver for a specific domain suffix (spec §6/§7.6).
type SplitDNSRoute struct {
	Domain   string `json:"domain"`
	Resolver string `json:"resolver"`
}

// ManagedRoute is a route RiftRoute intends to own (spec §5.1).
type ManagedRoute struct {
	Route
	ProfileID string    `json:"profile_id"`
	CreatedAt time.Time `json:"created_at"`
}

// ManagedRule is an ip rule RiftRoute intends to own (Linux Model B).
type ManagedRule struct {
	PolicyRule
	ProfileID string    `json:"profile_id"`
	CreatedAt time.Time `json:"created_at"`
}
