package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

func inputs(level domain.TelemetryLevel) Inputs {
	now := time.Date(2026, 10, 2, 23, 30, 0, 0, time.FixedZone("IRST", 12600))
	return Inputs{
		Level: level, Install: strings.Repeat("c", 32), Now: now,
		App: App{Version: "0.7.0", Channel: "stable", OS: "darwin", OSMajor: 15, Arch: "arm64", Service: true},
		Counts: map[string]int{
			KeyStarts: 2, KeyUnclean: 1, KeyInstalled: 1, KeyHelpersRepaired: 1, KeyDNSFailures: 3,
			TunnelKey("ikev2", TunnelConnected): 2, FailureKey("ikev2", "cert"): 1, TunnelKey("wireguard", TunnelDrop): 1,
		},
		Profiles: []domain.Profile{
			{Name: "Secret Office Apps", Enabled: true, Mode: domain.ModeExclude, Rules: []domain.Rule{
				{Type: domain.RuleCIDR, Value: "10.31.7.0/24", Comment: "the payroll server"},
				{Type: domain.RuleDomain, Value: "*.corp.example.org"},
				{Type: domain.RuleDomain, Value: "intranet.example.org"},
			}},
			{Name: "home-lab", Mode: domain.ModeTunnel, Tunnel: "office", Rules: []domain.Rule{{Type: domain.RuleIP, Value: "192.0.2.77"}}},
		},
		Lists:      []domain.List{{Name: "ads", Source: "https://lists.example.net/ads.txt"}, {Name: "mine", Static: []string{"198.51.100.0/24"}}},
		Tunnels:    []domain.TunnelStatus{{Name: "office-blu", Type: domain.TunnelIKEv2, Via: domain.TunnelViaDirect, WhenDown: domain.TunnelBlock}},
		KillSwitch: true, AutoApply: true,
		Audit: []domain.AuditEvent{
			{Actor: domain.ActorDaemon, Action: "apply", Result: "applied", Profile: "Secret Office Apps", Timing: &domain.ApplyTiming{TotalMS: 120}},
			{Actor: domain.ActorUI, Action: "apply", Result: "applied", Timing: &domain.ApplyTiming{TotalMS: 4200}},
			{Actor: domain.ActorUI, Action: "apply", Result: "refused", Reason: "guardrails: [gateway-capture]", Codes: []string{"gateway-capture"}},
			{Actor: domain.ActorUI, Action: "rollback", Result: "rolled_back", Reason: "the connection was lost", Codes: []string{"watchdog"}},
			{Actor: domain.ActorUI, Action: "rollback", Result: "rolled_back", Reason: "reverted on request"}, // before codes
			{Actor: domain.ActorUI, Action: "apply", Result: "failed", Reason: "route add 10.31.7.0/24: exit 1"},
			{Actor: domain.ActorDaemon, Action: "killswitch", Result: "disabled"},
			{Actor: domain.ActorUI, Action: "tunnel-connect", Result: "failed", Profile: "tunnel:office-blu", Reason: "vpn.example.org timed out"},
		},
	}
}

func TestBuildFull(t *testing.T) {
	r := Build(inputs(domain.TelemetryFull))
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if r.Day != "2026-10-02" { // 23:30 in Tehran is 20:00 UTC, the same day
		t.Errorf("day %s", r.Day)
	}
	u := r.Usage
	if u.Profiles != 2 || u.ProfilesEnabled != 1 || u.ProfileModes["exclude"] != 1 || u.ProfileModes["tunnel"] != 1 ||
		u.Rules["cidr"] != 1 || u.Rules["wildcard"] != 1 || u.Rules["domain"] != 1 || u.Rules["ip"] != 1 ||
		u.Lists != 2 || u.ListsRemote != 1 || u.Tunnels["ikev2"] != 1 || u.TunnelsBlock != 1 || u.TunnelsDirect != 1 ||
		!u.KillSwitch || u.SplitDNS || !u.AutoApply {
		t.Errorf("usage %+v", u)
	}
	a := r.Applies
	if a.Applied != 2 || a.Auto != 1 || a.Failed != 1 || a.Slow != 1 || a.MS["lt250"] != 1 || a.MS["lt5000"] != 1 ||
		a.Refused["gateway-capture"] != 1 || a.RolledBack["watchdog"] != 1 || a.RolledBack["other"] != 1 {
		t.Errorf("applies %+v", a)
	}
	if r.Events.KillSwitchSafeMode != 1 || r.Events.DNSFailures != 3 {
		t.Errorf("events %+v", r.Events)
	}
	if s := r.Tunnels["ikev2"]; s.Connected != 2 || s.Failed["cert"] != 1 {
		t.Errorf("ikev2 %+v", s)
	}
	if s := r.Tunnels["wireguard"]; s.Drops != 1 {
		t.Errorf("wireguard %+v", s)
	}
	if _, ok := r.Tunnels["openvpn"]; ok {
		t.Error("a type with nothing to say is left out")
	}
	// Nothing from the inputs' names, values, addresses or reasons is in it.
	b, _ := json.Marshal(r)
	for _, secret := range []string{"Secret", "payroll", "10.31", "corp.example", "intranet", "home-lab", "office", "192.0.2",
		"lists.example", "ads", "198.51", "connection was lost", "route add", "vpn.example", "guardrails:"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("report carries %q: %s", secret, b)
		}
	}
}

func TestBuildBasicHasNoUsage(t *testing.T) {
	r := Build(inputs(domain.TelemetryBasic))
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if r.Usage != nil || r.Applies != nil || r.Tunnels != nil || r.Events != nil {
		t.Fatalf("basic carries full fields: %+v", r)
	}
	if r.Daemon.Starts != 2 || r.Daemon.Unclean != 1 || r.Updates.Installed != 1 || r.Updates.HelpersRepaired != 1 {
		t.Fatalf("basic %+v", r)
	}
}
