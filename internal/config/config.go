// Package config parses and validates the declarative, git-committable config
// file (spec §10). YAML is the primary format (with precise line-referenced
// errors via the node tree); TOML is also accepted. Parsing and validation
// never mutate any system state.
package config

import (
	"fmt"
	"os"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
	yaml "gopkg.in/yaml.v3"

	"github.com/Amirhat/riftroute/internal/domain"
)

// Format is the on-disk config format.
type Format int

const (
	FormatYAML Format = iota
	FormatTOML
)

// Config mirrors the §10 schema. Fields are intentionally loose (strings for
// enums/durations) so validation — not the decoder — produces friendly,
// line-referenced diagnostics.
type Config struct {
	Version  int             `yaml:"version" toml:"version"`
	Settings Settings        `yaml:"settings" toml:"settings"`
	Profiles []ProfileConfig `yaml:"profiles" toml:"profiles"`
	Lists    []ListConfig    `yaml:"lists" toml:"lists"`
}

// Settings is the top-level settings block.
type Settings struct {
	IPVersion         []string          `yaml:"ip_version" toml:"ip_version"`
	DefaultMode       string            `yaml:"default_mode" toml:"default_mode"`
	AutoApplyOnChange bool              `yaml:"auto_apply_on_change" toml:"auto_apply_on_change"`
	KillSwitch        bool              `yaml:"kill_switch" toml:"kill_switch"`
	ConnectivityGuard ConnectivityGuard `yaml:"connectivity_guard" toml:"connectivity_guard"`
	SplitDNS          []SplitDNSConfig  `yaml:"split_dns" toml:"split_dns"`
}

// SplitDNSConfig is a per-domain resolver selection (spec §6/§7.6).
type SplitDNSConfig struct {
	Domain   string `yaml:"domain" toml:"domain"`
	Resolver string `yaml:"resolver" toml:"resolver"`
}

// ConnectivityGuard configures the watchdog/commit-confirm behavior (spec §2).
type ConnectivityGuard struct {
	Enabled        bool     `yaml:"enabled" toml:"enabled"`
	Anchors        []string `yaml:"anchors" toml:"anchors"`
	ConfirmTimeout string   `yaml:"confirm_timeout" toml:"confirm_timeout"`
	GuardWindow    string   `yaml:"guard_window" toml:"guard_window"`
}

// ProfileConfig is a profile entry in the config file.
type ProfileConfig struct {
	Name        string       `yaml:"name" toml:"name"`
	Description string       `yaml:"description" toml:"description"`
	Enabled     bool         `yaml:"enabled" toml:"enabled"`
	Mode        string       `yaml:"mode" toml:"mode"`
	Gateway     string       `yaml:"gateway" toml:"gateway"`
	Priority    int          `yaml:"priority" toml:"priority"`
	Rules       []RuleConfig `yaml:"rules" toml:"rules"`
	Lists       []string     `yaml:"lists" toml:"lists"`
	IPVersion   []string     `yaml:"ip_version" toml:"ip_version"`
}

// RuleConfig is a single rule entry.
type RuleConfig struct {
	Type    string `yaml:"type" toml:"type"`
	Value   string `yaml:"value" toml:"value"`
	Comment string `yaml:"comment" toml:"comment"`
}

// ListConfig is a reusable list entry (static or remote).
type ListConfig struct {
	Name    string   `yaml:"name" toml:"name"`
	Static  []string `yaml:"static" toml:"static"`
	Source  string   `yaml:"source" toml:"source"`
	Refresh string   `yaml:"refresh" toml:"refresh"`
}

// DetectFormat picks a format from a file extension (default YAML).
func DetectFormat(path string) Format {
	switch {
	case strings.HasSuffix(path, ".toml"):
		return FormatTOML
	default:
		return FormatYAML
	}
}

// ParseFile reads and parses+validates a config file. The returned error is for
// I/O failures only; syntax and semantic problems are reported in the result.
func ParseFile(path, platform string) (*Config, Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, Result{}, fmt.Errorf("read config: %w", err)
	}
	cfg, res := ParseBytes(data, DetectFormat(path), platform)
	return cfg, res, nil
}

// ParseBytes parses and validates config bytes. It always returns a Result;
// check res.OK(). The Config may be partially populated even when invalid.
func ParseBytes(data []byte, format Format, platform string) (*Config, Result) {
	var cfg Config
	var lines lineIndex

	switch format {
	case FormatTOML:
		if err := toml.Unmarshal(data, &cfg); err != nil {
			return nil, Result{Issues: []Issue{{Severity: SevError, Msg: "TOML parse error: " + err.Error()}}}
		}
	default: // YAML
		var root yaml.Node
		if err := yaml.Unmarshal(data, &root); err != nil {
			return nil, Result{Issues: []Issue{{Severity: SevError, Line: yamlErrLine(err), Msg: "YAML parse error: " + err.Error()}}}
		}
		if err := root.Decode(&cfg); err != nil {
			return nil, Result{Issues: []Issue{{Severity: SevError, Line: yamlErrLine(err), Msg: "YAML decode error: " + err.Error()}}}
		}
		lines = buildLineIndex(&root)
	}

	res := validate(&cfg, lines, platform)
	return &cfg, res
}

// ToDomain converts the parsed config into domain entities for the engine.
// Profile ids are derived from names (stable, human-readable) until the store
// assigns its own.
func (c *Config) ToDomain() ([]domain.Profile, []domain.List, error) {
	var profiles []domain.Profile
	for _, pc := range c.Profiles {
		p := domain.Profile{
			ID:          "cfg:" + pc.Name,
			Name:        pc.Name,
			Description: pc.Description,
			Enabled:     pc.Enabled,
			Mode:        domain.Mode(orDefault(pc.Mode, string(domain.ModeExclude))),
			Gateway:     orDefault(pc.Gateway, "auto"),
			Priority:    pc.Priority,
			Lists:       pc.Lists,
		}
		for _, fam := range pc.IPVersion {
			p.IPVersion = append(p.IPVersion, domain.Family(fam))
		}
		for _, rc := range pc.Rules {
			p.Rules = append(p.Rules, domain.Rule{Type: domain.RuleType(rc.Type), Value: rc.Value, Comment: rc.Comment})
		}
		profiles = append(profiles, p)
	}
	var lists []domain.List
	for _, lc := range c.Lists {
		lists = append(lists, domain.List{Name: lc.Name, Static: lc.Static, Source: lc.Source, Refresh: lc.Refresh})
	}
	return profiles, lists, nil
}

// FromDomain builds a declarative Config from live domain entities — the inverse
// of ToDomain, used by the GUI's "Export config" so anything assembled visually
// round-trips into the same git-committable YAML the CLI applies.
func FromDomain(profiles []domain.Profile, lists []domain.List, splitDNS []domain.SplitDNSRoute) *Config {
	c := &Config{Version: 1}
	for _, sd := range splitDNS {
		c.Settings.SplitDNS = append(c.Settings.SplitDNS, SplitDNSConfig{Domain: sd.Domain, Resolver: sd.Resolver})
	}
	for _, p := range profiles {
		pc := ProfileConfig{
			Name:        p.Name,
			Description: p.Description,
			Enabled:     p.Enabled,
			Mode:        string(p.Mode),
			Gateway:     p.Gateway,
			Priority:    p.Priority,
			Lists:       p.Lists,
		}
		for _, f := range p.IPVersion {
			pc.IPVersion = append(pc.IPVersion, string(f))
		}
		for _, r := range p.Rules {
			pc.Rules = append(pc.Rules, RuleConfig{Type: string(r.Type), Value: r.Value, Comment: r.Comment})
		}
		c.Profiles = append(c.Profiles, pc)
	}
	for _, l := range lists {
		c.Lists = append(c.Lists, ListConfig{Name: l.Name, Static: l.Static, Source: l.Source, Refresh: l.Refresh})
	}
	return c
}

// ToYAML renders the config as YAML bytes (export path). Named to avoid any
// resemblance to yaml.v3's Marshaler interface.
func (c *Config) ToYAML() ([]byte, error) { return yaml.Marshal(c) }

// SplitDNSRoutes returns the configured split-DNS routes as domain entities.
func (c *Config) SplitDNSRoutes() []domain.SplitDNSRoute {
	var out []domain.SplitDNSRoute
	for _, s := range c.Settings.SplitDNS {
		out = append(out, domain.SplitDNSRoute{Domain: s.Domain, Resolver: s.Resolver})
	}
	return out
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
