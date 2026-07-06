package config

import (
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

// the canonical §10 sample.
const sampleYAML = `version: 1

settings:
  ip_version: [v4, v6]
  default_mode: exclude
  auto_apply_on_change: true
  kill_switch: false
  connectivity_guard:
    enabled: true
    anchors: [gateway, "1.1.1.1"]
    confirm_timeout: 15s
    guard_window: 30s

profiles:
  - name: work-direct
    enabled: true
    mode: exclude
    gateway: auto
    priority: 100
    rules:
      - { type: cidr,   value: "10.0.0.0/8",  comment: "corp LAN" }
      - { type: domain, value: "jira.internal.example.com" }
    lists: [rfc1918]

  - name: only-tunnel-banking
    enabled: false
    mode: include
    rules:
      - { type: domain, value: "mybank.example.com" }
      - { type: asn,    value: "AS13335", comment: "Cloudflare" }

lists:
  - name: rfc1918
    static:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
  - name: cloudflare-ranges
    source: "https://www.cloudflare.com/ips-v4"
    refresh: 24h
`

func TestSampleValidOnLinux(t *testing.T) {
	cfg, res := ParseBytes([]byte(sampleYAML), FormatYAML, "linux")
	if cfg == nil {
		t.Fatal("nil config")
	}
	if res.HasErrors() {
		t.Fatalf("expected no errors, got:\n%s", res.String())
	}
	if len(cfg.Profiles) != 2 || len(cfg.Lists) != 2 {
		t.Fatalf("parse counts wrong: %d profiles, %d lists", len(cfg.Profiles), len(cfg.Lists))
	}
	profiles, lists, err := cfg.ToDomain()
	if err != nil || len(profiles) != 2 || len(lists) != 2 {
		t.Fatalf("ToDomain: %v profiles=%d lists=%d", err, len(profiles), len(lists))
	}
}

func TestSampleIncludeSupportedOnMacOS(t *testing.T) {
	// macOS now supports include mode (PF route-to), so the sample — which has an
	// include profile with domain/asn rules — must NOT warn about it.
	_, res := ParseBytes([]byte(sampleYAML), FormatYAML, "darwin")
	if res.HasErrors() {
		t.Fatalf("unexpected errors:\n%s", res.String())
	}
	for _, w := range res.Warnings() {
		if strings.Contains(w.Msg, "include mode") && strings.Contains(w.Msg, "unavailable") {
			t.Fatalf("macOS include mode should be supported now, got warning: %s", w.Msg)
		}
	}
}

func TestMacOSPerAppUIDError(t *testing.T) {
	// A macOS include profile whose app rule names a process (not a uid/username)
	// is an ERROR: PF matches on the socket owner and the engine refuses non-uid
	// values at apply time, so validation must catch it up front.
	const cfg = `version: 1
profiles:
  - name: tunnel-apps
    mode: include
    rules:
      - { type: app, value: "/Applications/Firefox.app" }
`
	_, res := ParseBytes([]byte(cfg), FormatYAML, "darwin")
	if !res.HasErrors() {
		t.Fatalf("expected a per-app uid error on macOS, got %+v", res.Issues)
	}
	var saw bool
	for _, e := range res.Errors() {
		if strings.Contains(e.Msg, "uid/username") {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("expected a uid/username error, got %+v", res.Errors())
	}
	// A numeric uid is accepted cleanly.
	_, res2 := ParseBytes([]byte(strings.Replace(cfg, `"/Applications/Firefox.app"`, `"501"`, 1)), FormatYAML, "darwin")
	if res2.HasErrors() {
		t.Fatalf("uid value should validate, got:\n%s", res2.String())
	}
	// On Linux the same app value is fine (cgroup matching takes any id).
	_, res3 := ParseBytes([]byte(cfg), FormatYAML, "linux")
	if res3.HasErrors() {
		t.Fatalf("app value should be accepted on linux, got:\n%s", res3.String())
	}
}

func TestValidateProfile(t *testing.T) {
	// A well-formed exclude profile passes.
	ok := domain.Profile{
		Name: "work", Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.0.0.0/8"}, {Type: domain.RuleIP, Value: "1.1.1.1"}},
	}
	if r := ValidateProfile(ok, "linux", nil); r.HasErrors() {
		t.Fatalf("valid profile should pass, got:\n%s", r.String())
	}

	// Missing name + invalid CIDR + invalid gateway all surface as errors.
	bad := domain.Profile{
		Mode: domain.ModeExclude, Gateway: "not-an-ip",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "999.999.999"}},
	}
	r := ValidateProfile(bad, "linux", nil)
	if !r.HasErrors() {
		t.Fatal("expected errors")
	}
	want := map[string]bool{"name": false, "gateway": false, "rules.value": false}
	for _, is := range r.Errors() {
		if _, ok := want[is.Field]; ok {
			want[is.Field] = true
		}
	}
	for field, seen := range want {
		if !seen {
			t.Errorf("expected an error on field %q; issues: %+v", field, r.Errors())
		}
	}

	// Unknown list reference errors when knownLists is provided.
	ul := ValidateProfile(domain.Profile{Name: "x", Lists: []string{"nope"}}, "linux", map[string]bool{"known": true})
	if !ul.HasErrors() {
		t.Fatal("unknown list reference should error")
	}

	// macOS include + non-uid app value is an error (would fail the pfctl load).
	mac := ValidateProfile(domain.Profile{
		Name: "apps", Mode: domain.ModeInclude,
		Rules: []domain.Rule{{Type: domain.RuleApp, Value: "/Applications/Firefox.app"}},
	}, "darwin", nil)
	if !mac.HasErrors() {
		t.Fatalf("expected a per-app uid error, got %+v", mac.Issues)
	}
	sawErr := false
	for _, e := range mac.Errors() {
		if strings.Contains(e.Msg, "uid/username") {
			sawErr = true
		}
	}
	if !sawErr {
		t.Fatalf("expected a uid/username error, got %+v", mac.Errors())
	}
	// The same profile with a uid passes.
	if r := ValidateProfile(domain.Profile{
		Name: "apps", Mode: domain.ModeInclude,
		Rules: []domain.Rule{{Type: domain.RuleApp, Value: "501"}},
	}, "darwin", nil); r.HasErrors() {
		t.Fatalf("uid app rule should pass: %s", r.String())
	}
}

func TestFromDomainExportRoundTrip(t *testing.T) {
	profiles := []domain.Profile{{
		ID: "gui:work", Name: "work", Description: "corp routes", Enabled: true,
		Mode: domain.ModeExclude, Gateway: "auto", Priority: 10,
		Rules: []domain.Rule{
			{Type: domain.RuleCIDR, Value: "10.0.0.0/8", Comment: "corp"},
			{Type: domain.RuleDomain, Value: "corp.example.com"},
		},
		Lists: []string{"corp-nets"},
	}}
	lists := []domain.List{{Name: "corp-nets", Static: []string{"172.16.0.0/12"}}}
	sdns := []domain.SplitDNSRoute{{Domain: "corp.example.com", Resolver: "10.0.0.53"}}

	data, err := FromDomain(profiles, lists, sdns).ToYAML()
	if err != nil {
		t.Fatal(err)
	}

	// The exported YAML must parse + validate cleanly and round-trip to the same
	// domain entities (the GUI export → import cycle).
	cfg, res := ParseBytes(data, FormatYAML, "linux")
	if res.HasErrors() {
		t.Fatalf("exported config does not validate:\n%s\n--- yaml ---\n%s", res.String(), data)
	}
	gotProfiles, gotLists, _ := cfg.ToDomain()
	if len(gotProfiles) != 1 || len(gotLists) != 1 {
		t.Fatalf("round-trip counts wrong: %d profiles %d lists", len(gotProfiles), len(gotLists))
	}
	p := gotProfiles[0]
	if p.Name != "work" || p.Description != "corp routes" || !p.Enabled || p.Priority != 10 ||
		len(p.Rules) != 2 || p.Rules[0].Value != "10.0.0.0/8" || len(p.Lists) != 1 {
		t.Fatalf("profile did not round-trip: %+v", p)
	}
	if got := cfg.SplitDNSRoutes(); len(got) != 1 || got[0].Resolver != "10.0.0.53" {
		t.Fatalf("split-DNS did not round-trip: %+v", got)
	}
}

func TestValidateList(t *testing.T) {
	if r := ValidateList(domain.List{Name: "ok", Static: []string{"10.0.0.0/8", "1.1.1.1"}}); r.HasErrors() {
		t.Fatalf("valid static list should pass: %s", r.String())
	}
	if r := ValidateList(domain.List{Name: "ok", Source: "https://example.com/x.txt", Refresh: "24h"}); r.HasErrors() {
		t.Fatalf("valid remote list should pass: %s", r.String())
	}
	for _, bad := range []domain.List{
		{Name: ""},  // no name, no entries
		{Name: "x"}, // neither static nor source
		{Name: "x", Static: []string{"999.999.999"}},                // bad entry
		{Name: "x", Source: "http://insecure.example"},              // non-https
		{Name: "x", Source: "https://ok.example", Refresh: "often"}, // bad duration
	} {
		if r := ValidateList(bad); !r.HasErrors() {
			t.Errorf("list %+v should be rejected", bad)
		}
	}
}

func TestLineReferencedErrors(t *testing.T) {
	const bad = `version: 1
profiles:
  - name: broken
    rules:
      - { type: cidr, value: "not-a-cidr" }
    lists: [does-not-exist]
`
	_, res := ParseBytes([]byte(bad), FormatYAML, "linux")
	if !res.HasErrors() {
		t.Fatal("expected errors")
	}
	var sawCIDR, sawList bool
	for _, e := range res.Errors() {
		if strings.Contains(e.Msg, "invalid CIDR") {
			sawCIDR = true
			if e.Line != 5 {
				t.Errorf("invalid CIDR should be line 5, got %d", e.Line)
			}
		}
		if strings.Contains(e.Msg, "unknown list") {
			sawList = true
			if e.Line != 6 {
				t.Errorf("unknown list ref should be line 6, got %d", e.Line)
			}
		}
	}
	if !sawCIDR || !sawList {
		t.Fatalf("missing expected errors; got:\n%s", res.String())
	}
}

func TestBadDurationAndVersion(t *testing.T) {
	const bad = `version: 2
settings:
  connectivity_guard:
    confirm_timeout: "15 bananas"
`
	_, res := ParseBytes([]byte(bad), FormatYAML, "linux")
	msgs := res.String()
	if !strings.Contains(msgs, "unsupported config version") {
		t.Errorf("expected version error, got:\n%s", msgs)
	}
	if !strings.Contains(msgs, "invalid duration") {
		t.Errorf("expected duration error, got:\n%s", msgs)
	}
}

func TestSplitDNSValidation(t *testing.T) {
	const src = `version: 1
settings:
  split_dns:
    - domain: corp.example.com
      resolver: 10.0.0.53
    - domain: "not a domain"
      resolver: "not-an-ip"
`
	cfg, res := ParseBytes([]byte(src), FormatYAML, "linux")
	msgs := res.String()
	if !strings.Contains(msgs, "invalid domain") {
		t.Errorf("expected domain error, got:\n%s", msgs)
	}
	if !strings.Contains(msgs, "resolver must be an IP") {
		t.Errorf("expected resolver error, got:\n%s", msgs)
	}
	routes := cfg.SplitDNSRoutes()
	if len(routes) != 2 || routes[0].Domain != "corp.example.com" || routes[0].Resolver != "10.0.0.53" {
		t.Fatalf("split-dns routes = %+v", routes)
	}
}

func TestTOMLAccepted(t *testing.T) {
	const tomlSrc = `version = 1
[settings]
default_mode = "exclude"

[[profiles]]
name = "p"
mode = "exclude"
[[profiles.rules]]
type = "cidr"
value = "10.0.0.0/8"
`
	cfg, res := ParseBytes([]byte(tomlSrc), FormatTOML, "linux")
	if cfg == nil || res.HasErrors() {
		t.Fatalf("TOML should parse cleanly, got:\n%s", res.String())
	}
	if len(cfg.Profiles) != 1 || len(cfg.Profiles[0].Rules) != 1 {
		t.Fatalf("TOML parse wrong: %+v", cfg.Profiles)
	}
}
