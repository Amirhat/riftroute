package bugreport

import (
	"strings"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// fixture mirrors a real affected machine: exclude profile with a wildcard
// domain, a VPN whose interface names its provider, and the log lines that
// machine actually produced.
func fixture() Input {
	now := time.Date(2026, 9, 23, 3, 0, 0, 0, time.UTC)
	return Input{
		Now: now,
		OS:  "macOS 15.6 (arm64)",
		State: domain.State{
			Health: domain.Health{
				Daemon: domain.DaemonOK, Provider: "macos", UptimeSeconds: 7200,
				Build:     domain.BuildInfo{Version: "0.2.4", Commit: "a5e49c21fa47e208", CommitTime: "2026-08-13T10:04:57Z"},
				Binary:    "/Library/PrivilegedHelperTools/riftrouted",
				StartedAt: now.Add(-2 * time.Hour), SchemaVersion: 2,
			},
			VPN:         domain.VPNStatus{Active: true, Interfaces: []string{"ipsec0", "windscribe0"}},
			Interfaces:  []domain.Iface{{Name: "en0", Up: true}, {Name: "ipsec0", Up: true, IsVPN: true}, {Name: "windscribe0", Up: true, IsVPN: true}},
			Defaults:    []domain.DefaultRoute{{Family: domain.FamilyV4, Present: true, Gateway: "192.168.88.1", Iface: "en0", Owner: domain.OwnerSystem}},
			DNS:         domain.DNSState{Servers: []string{"10.255.255.2", "1.1.1.1"}, SearchDomains: []string{"corp.internal"}},
			Drift:       domain.DriftStatus{Pending: true, Adds: 7, Reason: `profile "Home Bank": no physical gateway for v4`},
			Preferences: domain.DefaultPreferences(),
		},
		Profiles: []domain.Profile{{
			ID: "gui:home-bank-1", Name: "Home Bank", Description: "Amir's bank and tax office", Enabled: true,
			Mode: domain.ModeExclude, Gateway: "auto",
			Rules: []domain.Rule{
				{Type: domain.RuleDomain, Value: "*.jaryan.app", Comment: "salary portal"},
				{Type: domain.RuleCIDR, Value: "185.10.75.0/24"},
				{Type: domain.RuleCountry, Value: "IR"},
			},
		}},
		Lists:    []domain.List{{Name: "iran-banks", Source: "https://lists.example.net/banks.txt?token=s3cret", Static: []string{"bank.example.ir"}}},
		SplitDNS: []domain.SplitDNSRoute{{Domain: "corp.internal", Resolver: "10.0.0.53"}},
		Routes: []domain.Route{
			{DstCIDR: "0.0.0.0/0", Gateway: "192.168.88.1", Iface: "en0", Family: domain.FamilyV4, Owner: domain.OwnerSystem},
			{DstCIDR: "185.10.75.0/24", Gateway: "192.168.88.1", Iface: "en0", Family: domain.FamilyV4, Owner: domain.OwnerRiftRoute},
			{DstCIDR: "2a01:4f8::/32", Gateway: "fe80::1%en0", Iface: "en0", Family: domain.FamilyV6, Owner: domain.OwnerSystem},
		},
		Doctor: domain.DoctorReport{Checks: []domain.DoctorCheck{{Name: "gateway", Status: domain.CheckPass, Detail: "192.168.88.1 via en0"}}, Pass: 1},
		Audit:  []domain.AuditEvent{{TS: now, Actor: domain.ActorDaemon, Action: "reconcile", Profile: "Home Bank", Result: "committed", Reason: "added 185.10.75.0/24"}},
		Log: `time=2026-09-23T06:28:00.000+03:30 level=INFO msg="wildcard subdomain learned" rule=*.jaryan.app name=app.jaryan.app addrs=1
time=2026-09-23T06:29:00.000+03:30 level=WARN msg="reconcile skipped" err="profile \"Home Bank\": no physical gateway for v4"
time=2026-09-23T06:29:01.000+03:30 level=INFO msg="riftrouted listening" socket=/var/run/riftroute.sock db="/Users/amir/Library/Application Support/riftroute/riftroute-dev.db" host=Amirs-MacBook-Pro.local`,
		LogSource: "/var/log/riftroute/riftrouted.err.log",
		Hosts:     []string{"Amirs-MacBook-Pro.local", "Amirs-MacBook-Pro", "Amir’s MacBook Pro"},
		Users:     []string{"amir", "Amir Hosseini", "Amir", "Hosseini"},
	}
}

func TestReportLeaksNothingIdentifying(t *testing.T) {
	rep := Render(fixture())
	for _, secret := range []string{
		"Home Bank", "jaryan", "salary portal", "Amir", "Hosseini", "bank and tax", "iran-banks",
		"lists.example.net", "s3cret", "bank.example.ir", "corp.internal", "10.0.0.53", "192.168.88.1",
		"10.255.255.2", "185.10.75", "2a01:4f8", "fe80::1", "windscribe", "MacBook", "+03:30", `"IR"`, " IR",
	} {
		if strings.Contains(rep.Text, secret) {
			t.Errorf("report leaks %q", secret)
		}
	}
	if t.Failed() {
		t.Log(rep.Text)
	}
}

func TestReportKeepsWhatDebuggingNeeds(t *testing.T) {
	rep := Render(fixture())
	for _, want := range []string{
		"REVIEW BEFORE SHARING",
		"build      0.2.4 (a5e49c2, 2026-08-13)",
		"binary     /Library/PrivilegedHelperTools/riftrouted",
		"updates auto · telemetry full",
		"vpn        active (ipsec0, <iface-1>)", // generic tunnel names stay, branded ones go
		"default    v4: <ip4-lan-1> dev en0 [system] direct",
		"1.1.1.1", // public resolver kept
		"mode=exclude enabled=yes",
		"  domain  *.<domain-1>", // the wildcard's shape survives
		"  cidr    <ip4-1>/24",
		"[pass] gateway: <ip4-lan-1> via en0", // same gateway, same placeholder everywhere
		"v4 0.0.0.0/0 via <ip4-lan-1> dev en0 [system]",
		"no physical gateway for v4", // the actual error text
		"name=<sub-1>.<domain-1>",
		"2026-09-23T02:58:00.000Z",                                // log time in UTC
		"/Library/Application Support/riftroute/riftroute-dev.db", // path kept, user masked
		"pending transactions: 0",
	} {
		if !strings.Contains(rep.Text, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if rep.Redactions == 0 {
		t.Error("redaction count not reported")
	}
	if t.Failed() {
		t.Log(rep.Text)
	}
}

func TestGenericIface(t *testing.T) {
	for _, n := range []string{"en0", "utun4", "ipsec0", "wlp2s0", "enp0s31f6", "wg0", "lo0", "bridge100", "awdl0", "docker0", "tun0"} {
		if !GenericIface(n) {
			t.Errorf("%s should be generic", n)
		}
	}
	for _, n := range []string{"nordlynx", "wg-mullvad", "windscribe0", "proton0", "tailscale0", "ProtonVPN"} {
		if GenericIface(n) {
			t.Errorf("%s names a product and must be redacted", n)
		}
	}
}

func TestRoutesAndLogAreCapped(t *testing.T) {
	in := fixture()
	in.Routes = nil
	for i := 0; i < MaxRoutes+50; i++ {
		in.Routes = append(in.Routes, domain.Route{DstCIDR: "198.51.100.0/24", Iface: "en0", Family: domain.FamilyV4})
	}
	in.Log = strings.Repeat("line\n", MaxLogLines+100)
	rep := Render(in)
	if !strings.Contains(rep.Text, "… 50 more not shown") {
		t.Error("route cap not applied")
	}
	if n := strings.Count(rep.Text, "\nline"); n != MaxLogLines {
		t.Errorf("log lines = %d, want %d", n, MaxLogLines)
	}
}
