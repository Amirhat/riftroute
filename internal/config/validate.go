package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v3"

	"github.com/Amirhat/riftroute/internal/domain"
)

// Severity is the level of a validation Issue.
type Severity string

const (
	SevError   Severity = "error"
	SevWarning Severity = "warning"
)

// Issue is a single validation diagnostic, line-referenced where possible.
type Issue struct {
	Severity Severity `json:"severity"`
	Line     int      `json:"line,omitempty"`
	Field    string   `json:"field,omitempty"`
	Msg      string   `json:"msg"`
}

// Result is the outcome of validation.
type Result struct {
	Issues []Issue `json:"issues"`
}

// OK reports whether the config has no error-severity issues (warnings allowed).
func (r Result) OK() bool { return !r.HasErrors() }

// HasErrors reports whether any issue is error severity.
func (r Result) HasErrors() bool {
	for _, i := range r.Issues {
		if i.Severity == SevError {
			return true
		}
	}
	return false
}

// Errors returns only the error-severity issues.
func (r Result) Errors() []Issue { return r.filter(SevError) }

// Warnings returns only the warning-severity issues.
func (r Result) Warnings() []Issue { return r.filter(SevWarning) }

func (r Result) filter(s Severity) []Issue {
	var out []Issue
	for _, i := range r.Issues {
		if i.Severity == s {
			out = append(out, i)
		}
	}
	return out
}

// String renders the result as multi-line, line-referenced diagnostics.
func (r Result) String() string {
	if len(r.Issues) == 0 {
		return "config OK"
	}
	var b strings.Builder
	for _, i := range r.Issues {
		loc := ""
		if i.Line > 0 {
			loc = fmt.Sprintf("line %d: ", i.Line)
		}
		field := ""
		if i.Field != "" {
			field = " (" + i.Field + ")"
		}
		fmt.Fprintf(&b, "%s: %s%s%s\n", i.Severity, loc, i.Msg, field)
	}
	return strings.TrimRight(b.String(), "\n")
}

var (
	reASN     = regexp.MustCompile(`(?i)^AS\d+$`)
	reCountry = regexp.MustCompile(`^[A-Za-z]{2}$`)
	reLabel   = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
)

// validate runs all semantic checks. platform is "darwin"/"linux"/"fake" and
// governs OS-specific warnings (e.g. include mode needs Linux Model B).
func validate(c *Config, lines lineIndex, platform string) Result {
	var r Result
	add := func(sev Severity, path, field, msg string) {
		r.Issues = append(r.Issues, Issue{Severity: sev, Line: lines.lineOf(path), Field: field, Msg: msg})
	}

	if c.Version != 1 {
		add(SevError, "version", "version", fmt.Sprintf("unsupported config version %d (expected 1)", c.Version))
	}

	// settings
	for i, v := range c.Settings.IPVersion {
		if v != "v4" && v != "v6" {
			add(SevError, fmt.Sprintf("settings.ip_version[%d]", i), "settings.ip_version", fmt.Sprintf("invalid ip_version %q (expected v4 or v6)", v))
		}
	}
	if m := c.Settings.DefaultMode; m != "" && m != "exclude" && m != "include" {
		add(SevError, "settings.default_mode", "settings.default_mode", fmt.Sprintf("invalid default_mode %q (expected exclude or include)", m))
	}
	cg := c.Settings.ConnectivityGuard
	checkDuration(add, "settings.connectivity_guard.confirm_timeout", "confirm_timeout", cg.ConfirmTimeout)
	checkDuration(add, "settings.connectivity_guard.guard_window", "guard_window", cg.GuardWindow)
	for i, a := range cg.Anchors {
		if a == "gateway" {
			continue
		}
		if _, err := netip.ParseAddr(a); err != nil {
			add(SevError, fmt.Sprintf("settings.connectivity_guard.anchors[%d]", i), "anchors", fmt.Sprintf("invalid anchor %q (expected \"gateway\" or an IP)", a))
		}
	}
	for i, sd := range c.Settings.SplitDNS {
		base := fmt.Sprintf("settings.split_dns[%d]", i)
		if !isValidDomain(sd.Domain) {
			add(SevError, base+".domain", "split_dns.domain", fmt.Sprintf("invalid domain %q", sd.Domain))
		}
		if _, err := netip.ParseAddr(sd.Resolver); err != nil {
			add(SevError, base+".resolver", "split_dns.resolver", fmt.Sprintf("resolver must be an IP, got %q", sd.Resolver))
		}
	}

	// known list names (for profile.lists references)
	known := map[string]bool{}
	seenList := map[string]bool{}
	for i, l := range c.Lists {
		base := fmt.Sprintf("lists[%d]", i)
		if strings.TrimSpace(l.Name) == "" {
			add(SevError, base+".name", "lists.name", "list name is required")
		} else {
			if seenList[l.Name] {
				add(SevError, base+".name", "lists.name", fmt.Sprintf("duplicate list name %q", l.Name))
			}
			seenList[l.Name] = true
			known[l.Name] = true
		}
		if l.Source == "" && len(l.Static) == 0 {
			add(SevError, base, "lists", fmt.Sprintf("list %q must have either static entries or a remote source", l.Name))
		}
		for j, e := range l.Static {
			if !isCIDROrIP(e) {
				add(SevError, fmt.Sprintf("%s.static[%d]", base, j), "lists.static", fmt.Sprintf("invalid CIDR/IP %q", e))
			}
		}
		if l.Source != "" {
			if u, err := url.Parse(l.Source); err != nil || u.Scheme != "https" {
				add(SevError, base+".source", "lists.source", fmt.Sprintf("remote list source must be an https URL, got %q", l.Source))
			}
			checkDuration(add, base+".refresh", "lists.refresh", l.Refresh)
		}
	}

	// profiles
	seenProfile := map[string]bool{}
	for i, p := range c.Profiles {
		base := fmt.Sprintf("profiles[%d]", i)
		if strings.TrimSpace(p.Name) == "" {
			add(SevError, base+".name", "profiles.name", "profile name is required")
		} else {
			if seenProfile[p.Name] {
				add(SevError, base+".name", "profiles.name", fmt.Sprintf("duplicate profile name %q", p.Name))
			}
			seenProfile[p.Name] = true
		}
		mode := p.Mode
		if mode == "" {
			mode = "exclude"
		}
		if mode != "exclude" && mode != "include" {
			add(SevError, base+".mode", "profiles.mode", fmt.Sprintf("invalid mode %q (expected exclude or include)", p.Mode))
		}
		if mode == "include" && platform == "darwin" {
			// macOS supports include mode via PF route-to anchors. `app` rules there
			// match on the socket owner (uid/username), not a process name — and the
			// engine refuses non-uid values at apply time (they'd fail the pfctl
			// load), so surface it as an ERROR here rather than a late apply failure.
			for j, rule := range p.Rules {
				if rule.Type == "app" && rule.Value != "" && !domain.IsUIDLike(rule.Value) {
					add(SevError, fmt.Sprintf("%s.rules[%d].value", base, j), "rules.value",
						fmt.Sprintf("on macOS, per-app rules match by uid/username (PF socket owner); %q is not a uid/username", rule.Value))
				}
			}
		}
		if mode == "exclude" {
			// The engine only consumes app rules in include mode (they steer traffic
			// INTO the tunnel); in exclude mode they'd be silently ignored — surface
			// that instead of letting the user believe the rule does something.
			for j, rule := range p.Rules {
				if rule.Type == "app" {
					add(SevError, fmt.Sprintf("%s.rules[%d]", base, j), "rules.type",
						"per-app rules only take effect in include mode — switch the profile to include, or remove the app rule")
				}
			}
		}
		if g := p.Gateway; g != "" && g != "auto" {
			if _, err := netip.ParseAddr(g); err != nil {
				add(SevError, base+".gateway", "profiles.gateway", fmt.Sprintf("gateway must be \"auto\" or a valid IP, got %q", g))
			}
		}
		for _, ref := range p.Lists {
			if !known[ref] {
				add(SevError, base+".lists", "profiles.lists", fmt.Sprintf("profile %q references unknown list %q", p.Name, ref))
			}
		}
		if len(p.Rules) == 0 && len(p.Lists) == 0 {
			add(SevWarning, base, "profiles", fmt.Sprintf("profile %q has no rules or lists; it will install nothing", p.Name))
		}
		for j, rule := range p.Rules {
			validateRule(add, fmt.Sprintf("%s.rules[%d]", base, j), rule)
		}
	}

	sort.SliceStable(r.Issues, func(a, b int) bool { return r.Issues[a].Line < r.Issues[b].Line })
	return r
}

// ValidateProfile runs the same semantic checks a config-file profile receives,
// but against a single profile the GUI builder assembled (spec §10) — so the
// interactive designer gets identical strict validation to `apply file.yaml`.
// platform gates OS-specific notes (macOS per-app matches by uid/username);
// knownLists is the set of defined list names for `lists:` references (nil skips
// that check, e.g. when the builder only emits inline rules).
func ValidateProfile(p domain.Profile, platform string, knownLists map[string]bool) Result {
	var r Result
	add := func(sev Severity, field, msg string) {
		r.Issues = append(r.Issues, Issue{Severity: sev, Field: field, Msg: msg})
	}
	if strings.TrimSpace(p.Name) == "" {
		add(SevError, "name", "profile name is required")
	}
	mode := string(p.Mode)
	if mode == "" {
		mode = "exclude"
	}
	if mode != "exclude" && mode != "include" {
		add(SevError, "mode", fmt.Sprintf("invalid mode %q (expected exclude or include)", p.Mode))
	}
	if mode == "include" && platform == "darwin" {
		for _, rule := range p.Rules {
			if rule.Type == domain.RuleApp && rule.Value != "" && !domain.IsUIDLike(rule.Value) {
				add(SevError, "rules.value",
					fmt.Sprintf("on macOS, per-app rules match by uid/username (PF socket owner); %q is not a uid/username", rule.Value))
			}
		}
	}
	if mode == "exclude" {
		for _, rule := range p.Rules {
			if rule.Type == domain.RuleApp {
				add(SevError, "rules.type",
					"per-app rules only take effect in include mode — switch the profile to include, or remove the app rule")
			}
		}
	}
	if g := p.Gateway; g != "" && g != "auto" {
		if _, err := netip.ParseAddr(g); err != nil {
			add(SevError, "gateway", fmt.Sprintf("gateway must be \"auto\" or a valid IP, got %q", g))
		}
	}
	for _, ref := range p.Lists {
		if knownLists != nil && !knownLists[ref] {
			add(SevError, "lists", fmt.Sprintf("references unknown list %q", ref))
		}
	}
	if len(p.Rules) == 0 && len(p.Lists) == 0 {
		add(SevWarning, "rules", "profile has no rules or lists; it will install nothing")
	}
	// Reuse the file-path per-rule validation (CIDR/IP/domain/asn/country/app).
	radd := func(sev Severity, _, field, msg string) { add(sev, field, msg) }
	for i, rule := range p.Rules {
		validateRule(radd, fmt.Sprintf("rules[%d]", i), RuleConfig{Type: string(rule.Type), Value: rule.Value, Comment: rule.Comment})
	}
	return r
}

func validateRule(add func(Severity, string, string, string), base string, rule RuleConfig) {
	if strings.TrimSpace(rule.Value) == "" {
		add(SevError, base+".value", "rules.value", "rule value is required")
		return
	}
	switch rule.Type {
	case "cidr":
		if _, err := netip.ParsePrefix(rule.Value); err != nil {
			add(SevError, base+".value", "rules.value", fmt.Sprintf("invalid CIDR %q", rule.Value))
		}
	case "ip":
		if _, err := netip.ParseAddr(rule.Value); err != nil {
			add(SevError, base+".value", "rules.value", fmt.Sprintf("invalid IP %q", rule.Value))
		}
	case "domain":
		if !isValidDomain(rule.Value) {
			add(SevError, base+".value", "rules.value", fmt.Sprintf("invalid domain %q", rule.Value))
		}
	case "asn":
		if !reASN.MatchString(rule.Value) {
			add(SevError, base+".value", "rules.value", fmt.Sprintf("invalid ASN %q (expected form ASNNNN)", rule.Value))
		}
	case "country":
		if !reCountry.MatchString(rule.Value) {
			add(SevError, base+".value", "rules.value", fmt.Sprintf("invalid country code %q (expected 2 letters)", rule.Value))
		}
	case "app":
		// app rules are validated at apply time against the OS; only presence here.
	case "":
		add(SevError, base+".type", "rules.type", "rule type is required (cidr|ip|domain|asn|country|app)")
	default:
		add(SevError, base+".type", "rules.type", fmt.Sprintf("unknown rule type %q", rule.Type))
	}
}

func checkDuration(add func(Severity, string, string, string), path, field, v string) {
	if v == "" {
		return
	}
	if _, err := time.ParseDuration(v); err != nil {
		add(SevError, path, field, fmt.Sprintf("invalid duration %q", v))
	}
}

// ValidateList runs the same semantic checks a config-file list receives, against
// a single list the GUI lists manager assembled: named, static-or-remote, valid
// CIDR/IP entries, https-only source, parseable refresh interval.
func ValidateList(l domain.List) Result {
	var r Result
	add := func(sev Severity, field, msg string) {
		r.Issues = append(r.Issues, Issue{Severity: sev, Field: field, Msg: msg})
	}
	if strings.TrimSpace(l.Name) == "" {
		add(SevError, "name", "list name is required")
	}
	if l.Source == "" && len(l.Static) == 0 {
		add(SevError, "entries", "a list needs static entries or a remote source")
	}
	for _, e := range l.Static {
		if !isCIDROrIP(e) {
			add(SevError, "entries", fmt.Sprintf("invalid CIDR/IP %q", e))
		}
	}
	if l.Source != "" {
		if u, err := url.Parse(l.Source); err != nil || u.Scheme != "https" {
			add(SevError, "source", fmt.Sprintf("remote list source must be an https URL, got %q", l.Source))
		}
		if l.Refresh != "" {
			if _, err := time.ParseDuration(l.Refresh); err != nil {
				add(SevError, "refresh", fmt.Sprintf("invalid refresh interval %q (e.g. 24h)", l.Refresh))
			}
		}
	}
	return r
}

func isCIDROrIP(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// IsValidDomain reports whether s is a valid domain per the config schema
// (≥2 labels, ≤253 chars, one optional leading "*." wildcard). Exported for the
// API's split-DNS validation so every entry path shares one definition.
func IsValidDomain(s string) bool { return isValidDomain(s) }

func isValidDomain(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	// allow a single leading wildcard label
	s = strings.TrimPrefix(s, "*.")
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !reLabel.MatchString(l) {
			return false
		}
	}
	return true
}

// --- YAML line indexing ---

// lineIndex maps a dotted/indexed field path (e.g. "profiles[0].rules[1].value")
// to its 1-based source line, enabling line-referenced diagnostics.
type lineIndex map[string]int

func (li lineIndex) lineOf(path string) int {
	if li == nil {
		return 0
	}
	if l, ok := li[path]; ok {
		return l
	}
	// fall back to the nearest containing path so a field always resolves to a
	// sensible nearby line.
	for path != "" {
		if i := strings.LastIndexAny(path, ".["); i >= 0 {
			path = path[:i]
			if l, ok := li[path]; ok {
				return l
			}
		} else {
			break
		}
	}
	return 0
}

func buildLineIndex(root *yaml.Node) lineIndex {
	idx := lineIndex{}
	var walk func(prefix string, n *yaml.Node)
	walk = func(prefix string, n *yaml.Node) {
		switch n.Kind {
		case yaml.DocumentNode:
			for _, c := range n.Content {
				walk(prefix, c)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i], n.Content[i+1]
				path := k.Value
				if prefix != "" {
					path = prefix + "." + k.Value
				}
				idx[path] = k.Line
				walk(path, v)
			}
		case yaml.SequenceNode:
			for i, c := range n.Content {
				path := fmt.Sprintf("%s[%d]", prefix, i)
				idx[path] = c.Line
				walk(path, c)
			}
		case yaml.ScalarNode:
			if prefix != "" {
				idx[prefix] = n.Line
			}
		}
	}
	walk("", root)
	return idx
}

func yamlErrLine(err error) int {
	// yaml.v3 type errors carry "line N:" in their message.
	if te, ok := err.(*yaml.TypeError); ok && len(te.Errors) > 0 {
		err = fmt.Errorf("%s", te.Errors[0])
	}
	var line int
	if _, e := fmt.Sscanf(err.Error(), "yaml: line %d:", &line); e == nil {
		return line
	}
	return 0
}
