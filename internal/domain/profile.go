package domain

import (
	"strings"
	"time"
)

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

// IsUIDLike reports whether s is a valid macOS per-app selector: a numeric uid
// or a POSIX-ish username. On Darwin, PF matches per-app traffic by socket owner
// (`user <uid>`), and the value is interpolated into a pfctl rule — so the
// charset is strictly limited (one bad value would fail the whole anchor load).
// Shared by config validation and the routing engine so there is exactly one
// definition of "acceptable app selector on macOS".
func IsUIDLike(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// DomainRuleHost returns the resolvable hostname for a domain rule value.
// DNS cannot enumerate a wildcard's subdomains, so "*.example.com" resolves
// (and routes) its apex "example.com"; subdomain coverage comes from split-DNS,
// whose per-domain resolvers match suffixes natively. Shared by the domain
// resolver, the re-resolver, and split-DNS so a wildcard means the same thing
// everywhere instead of leaking into a literal "*.example.com" DNS query.
func DomainRuleHost(v string) string { return strings.TrimPrefix(v, "*.") }

// Profile is the unit a user toggles (spec §5.1).
type Profile struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"` // free-text note (GUI builder metadata)
	Enabled     bool     `json:"enabled"`
	Mode        Mode     `json:"mode"`
	Gateway     string   `json:"gateway"` // "auto" or an explicit IP
	Priority    int      `json:"priority"`
	Rules       []Rule   `json:"rules"`
	Lists       []string `json:"lists"`
	IPVersion   []Family `json:"ip_version,omitempty"`
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
	// Port is a non-standard resolver port (0 = 53). Used by the wildcard DNS
	// learner, whose loopback forwarder binds a dynamic port.
	Port int `json:"port,omitempty"`
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
