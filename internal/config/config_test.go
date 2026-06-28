package config

import (
	"strings"
	"testing"
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

func TestSampleWarnsIncludeOnMacOS(t *testing.T) {
	_, res := ParseBytes([]byte(sampleYAML), FormatYAML, "darwin")
	if res.HasErrors() {
		t.Fatalf("unexpected errors:\n%s", res.String())
	}
	w := res.Warnings()
	if len(w) != 1 || !strings.Contains(w[0].Msg, "include mode") {
		t.Fatalf("expected 1 include-mode warning on macOS, got %+v", w)
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
