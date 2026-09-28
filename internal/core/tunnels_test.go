package core

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/routing"
)

// withTunnels wires fixed tunnel inputs and statuses (the manager's Inputs and
// List) into svc; every input is reported connected.
func withTunnels(svc *Service, ins ...routing.TunnelInput) {
	svc.SetTunnels(func() []routing.TunnelInput { return ins }, func() []domain.TunnelStatus {
		var out []domain.TunnelStatus
		for _, in := range ins {
			st := domain.TunnelStatus{Name: in.Name, Routes: in.Routes, State: domain.TunnelDisconnected}
			if in.Iface != "" {
				st.State, st.Iface = domain.TunnelConnected, in.Iface
			}
			out = append(out, st)
		}
		return out
	})
}

func blockedReasons(ts []domain.TunnelStatus) map[string]string {
	out := map[string]string{}
	for _, t := range ts {
		for _, b := range t.Blocked {
			out[t.Name+" "+b.Route] = b.Reason
		}
	}
	return out
}

// Every route the engine leaves out reaches the tunnel's status with its
// reason: a destination another tunnel already routes, and a v6 route into a
// tunnel without IPv6 (which used to vanish silently).
func TestTunnelStatusReportsEveryRouteLeftOut(t *testing.T) {
	svc := newSvc(t)
	withTunnels(svc,
		routing.TunnelInput{Name: "a", Iface: "utun6", Routes: []string{"10.20.0.0/16"}},
		routing.TunnelInput{Name: "b", Iface: "utun7", Routes: []string{"10.20.0.0/16", "fd00::/8", "10.30.0.0/16"}},
	)
	got := blockedReasons(svc.TunnelStatuses(context.Background()))
	if !strings.Contains(got["b 10.20.0.0/16"], "tunnel a") {
		t.Errorf("duplicate destination not reported: %v", got)
	}
	if !strings.Contains(got["b fd00::/8"], "no IPv6") {
		t.Errorf("v6 route into a v4-only tunnel not reported: %v", got)
	}
	if len(got) != 2 {
		t.Errorf("blocked = %v, want exactly those two", got)
	}
}

func tunnelCheck(t *testing.T, svc *Service, name string) domain.DoctorCheck {
	t.Helper()
	for _, c := range svc.Doctor(context.Background()).Checks {
		if c.Name == "tunnel:"+name {
			return c
		}
	}
	t.Fatalf("no doctor check for tunnel %s", name)
	return domain.DoctorCheck{}
}

// The doctor checks a connected tunnel against the kernel, not its state
// alone: no interface, or routes missing from the table (an apply refused or
// still retrying, routes dropped with the tun), is not a PASS — and the count
// is what really goes through it, not what was listed.
func TestDoctorChecksTunnelsAgainstTheKernel(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()

	withTunnels(svc, routing.TunnelInput{Name: "infra", Routes: []string{"192.168.70.0/24"}})
	svc.tunnelStatus = func() []domain.TunnelStatus { // connected, but no interface found
		return []domain.TunnelStatus{{Name: "infra", Routes: []string{"192.168.70.0/24"}, State: domain.TunnelConnected}}
	}
	if c := tunnelCheck(t, svc, "infra"); c.Status != domain.CheckFail {
		t.Errorf("no interface: %s %q, want FAIL", c.Status, c.Detail)
	}

	withTunnels(svc, routing.TunnelInput{Name: "infra", Iface: "utun6", Routes: []string{"192.168.70.0/24", "192.168.72.0/24", "fd00::/8"}})
	c := tunnelCheck(t, svc, "infra")
	if c.Status == domain.CheckPass || !strings.Contains(c.Detail, "192.168.70.0/24") {
		t.Errorf("routes not in the kernel: %s %q, want them reported", c.Status, c.Detail)
	}

	desired, _, _, err := svc.DesiredTunnelsOnly(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range desired {
		if d.DstCIDR == "192.168.70.0/24" {
			if err := svc.Provider().AddRoute(ctx, d); err != nil {
				t.Fatal(err)
			}
		}
	}
	c = tunnelCheck(t, svc, "infra")
	if !strings.Contains(c.Detail, "1 route(s) through it") || !strings.Contains(c.Detail, "192.168.72.0/24") || !strings.Contains(c.Detail, "fd00::/8") {
		t.Errorf("one route in, one missing, one blocked: %s %q", c.Status, c.Detail)
	}

	for _, d := range desired {
		if d.DstCIDR == "192.168.72.0/24" {
			if err := svc.Provider().AddRoute(ctx, d); err != nil {
				t.Fatal(err)
			}
		}
	}
	withTunnels(svc, routing.TunnelInput{Name: "infra", Iface: "utun6", Routes: []string{"192.168.70.0/24", "192.168.72.0/24"}})
	if c := tunnelCheck(t, svc, "infra"); c.Status != domain.CheckPass || !strings.Contains(c.Detail, "2 route(s) through it") {
		t.Errorf("all installed: %s %q, want PASS with 2 routes", c.Status, c.Detail)
	}
}

// Drift reads the kernel for the tunnels' routes: one the ownership map holds
// but the kernel dropped (with its interface) is pending, not "in sync".
func TestDriftSeesTunnelRoutesTheKernelDropped(t *testing.T) {
	svc := newSvc(t)
	withTunnels(svc, routing.TunnelInput{Name: "infra", Iface: "utun6", Routes: []string{"192.168.70.0/24"}})
	ctx := context.Background()
	desired, _, _, err := svc.DesiredManaged(ctx)
	if err != nil || len(desired) != 1 {
		t.Fatalf("desired = %+v, %v", desired, err)
	}
	if err := svc.Store().AddOwned(desired[0]); err != nil { // owned, but not in the (fake) kernel
		t.Fatal(err)
	}
	st, err := svc.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Drift.Pending || st.Drift.Adds != 1 {
		t.Fatalf("drift = %+v, want the missing route pending", st.Drift)
	}
}

// A tunnel route containing the resolver in use would send every name lookup
// into the tunnel, and one containing the watchdog's canary would make the
// check guarding every change probe through it: both are left out. A resolver
// the user pointed a domain at (split DNS) is often behind the tunnel on
// purpose, and doesn't count.
func TestTunnelRoutesKeepDNSAndTheCanaryOut(t *testing.T) {
	svc := newSvc(t)
	svc.Provider().(*fake.Provider).SetDNS("10.255.255.1", "192.168.70.53")
	if err := svc.Store().SaveSplitDNS([]domain.SplitDNSRoute{{Domain: "corp.example", Resolver: "192.168.70.53"}}); err != nil {
		t.Fatal(err)
	}
	withTunnels(svc, routing.TunnelInput{Name: "infra", Iface: "utun6", Routes: []string{"10.0.0.0/8", "1.1.1.0/24", "192.168.70.0/24", "172.16.0.0/12"}})
	ctx := context.Background()

	got := blockedReasons(svc.TunnelStatuses(ctx))
	if !strings.Contains(got["infra 10.0.0.0/8"], "DNS server 10.255.255.1") {
		t.Errorf("route holding the resolver not reported: %v", got)
	}
	if !strings.Contains(got["infra 1.1.1.0/24"], "1.1.1.1") {
		t.Errorf("route holding the canary not reported: %v", got)
	}
	if len(got) != 2 {
		t.Errorf("blocked = %v, want exactly those two", got)
	}
	desired, _, _, err := svc.DesiredManaged(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var routes []string
	for _, d := range desired {
		routes = append(routes, d.DstCIDR)
	}
	if strings.Join(routes, ",") != "172.16.0.0/12,192.168.70.0/24" {
		t.Errorf("desired = %v", routes)
	}
}

// openvpn matters to OpenVPN tunnels only: with WireGuard tunnels alone, a
// missing openvpn is no failure, and a failed WireGuard tunnel's fix points
// at its configuration.
func TestDoctorChecksOpenVPNOnlyForOpenVPNTunnels(t *testing.T) {
	svc := newSvc(t)
	svc.SetTunnelEngine(func() domain.TunnelEngine { return domain.TunnelEngine{Problem: "OpenVPN isn't installed"} })
	engine := func() *domain.DoctorCheck {
		for _, c := range svc.Doctor(context.Background()).Checks {
			if c.Name == "tunnel-engine" {
				return &c
			}
		}
		return nil
	}
	svc.tunnelStatus = func() []domain.TunnelStatus {
		return []domain.TunnelStatus{{Name: "lab", Type: domain.TunnelWireGuard, State: domain.TunnelFailed, LastError: "no handshake"}}
	}
	if c := engine(); c != nil {
		t.Errorf("WireGuard only: tunnel-engine = %+v", c)
	}
	if c := tunnelCheck(t, svc, "lab"); c.Status != domain.CheckFail || !strings.Contains(c.Fix, "fix the configuration") {
		t.Errorf("failed WireGuard tunnel: %+v", c)
	}
	svc.tunnelStatus = func() []domain.TunnelStatus {
		return []domain.TunnelStatus{
			{Name: "lab", Type: domain.TunnelWireGuard, State: domain.TunnelDisconnected},
			{Name: "office", Type: domain.TunnelOpenVPN, State: domain.TunnelDisconnected},
		}
	}
	if c := engine(); c == nil || c.Status != domain.CheckFail {
		t.Errorf("with an OpenVPN tunnel: tunnel-engine = %+v, want FAIL", c)
	}
}

// A lookup names the tunnel the traffic goes into: by the route's tag in the
// desired set, and by a live tunnel's interface in the kernel's decision
// (macOS routes carry no tag) — not only "via VPN".
func TestMarkTunnelNamesTheTunnel(t *testing.T) {
	ts := []domain.TunnelStatus{
		{Name: "con3", Type: domain.TunnelWireGuard, State: domain.TunnelConnected, Iface: "utun8"},
		{Name: "old", Type: domain.TunnelOpenVPN, State: domain.TunnelDisconnected, Iface: "utun9"},
	}
	kernel := domain.RouteDecision{Reachable: true, Iface: "utun8", ViaVPN: true}
	markTunnel(&kernel, ts)
	if kernel.Tunnel != "con3" || kernel.TunnelType != domain.TunnelWireGuard {
		t.Errorf("kernel decision = %+v", kernel)
	}
	desired := domain.RouteDecision{Reachable: true, Iface: "utun8", Profile: "tunnel:con3"}
	markTunnel(&desired, ts)
	if desired.Tunnel != "con3" || desired.TunnelType != domain.TunnelWireGuard {
		t.Errorf("desired decision = %+v", desired)
	}
	for _, d := range []domain.RouteDecision{
		{Reachable: true, Iface: "utun4", ViaVPN: true}, // the main VPN
		{Reachable: true, Iface: "utun9"},               // a tunnel that's down
		{Reachable: false, Iface: "utun8"},
	} {
		markTunnel(&d, ts)
		if d.Tunnel != "" {
			t.Errorf("%+v was taken for a tunnel", d)
		}
	}
}

// The tunnel's status lists the tunnel-mode profiles routed into it — with
// their toggle state and how much each sends in — and checks their
// destinations like its own routes.
func TestTunnelStatusListsItsProfiles(t *testing.T) {
	svc := newSvc(t)
	for _, p := range []domain.Profile{
		{ID: "a", Name: "via con3", Enabled: true, Mode: domain.ModeTunnel, Tunnel: "con3",
			Rules: []domain.Rule{{Type: domain.RuleIP, Value: "9.9.9.9"}, {Type: domain.RuleCIDR, Value: "10.20.0.0/24"}}},
		{ID: "b", Name: "off", Enabled: false, Mode: domain.ModeTunnel, Tunnel: "con3",
			Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "172.16.0.0/12"}}},
		{ID: "c", Name: "elsewhere", Enabled: true, Mode: domain.ModeTunnel, Tunnel: "other",
			Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "192.0.2.0/24"}}},
	} {
		if err := svc.Store().UpsertProfile(p); err != nil {
			t.Fatal(err)
		}
	}
	svc.tunnelStatus = func() []domain.TunnelStatus {
		return []domain.TunnelStatus{{Name: "con3", Type: domain.TunnelWireGuard, State: domain.TunnelDisconnected}}
	}
	ts := svc.TunnelStatuses(context.Background())
	if len(ts) != 1 {
		t.Fatalf("statuses = %+v", ts)
	}
	got := ts[0].Profiles
	if len(got) != 2 || got[0].Name != "off" || got[0].Enabled || got[0].Routes != 0 || got[1].Name != "via con3" || !got[1].Enabled || got[1].Routes != 2 {
		t.Fatalf("profiles of con3 = %+v", got)
	}
}

// On macOS the kernel's refusal carries no tag: the lookup finds whose it
// is by the most specific owned reject route holding the target, and names
// that tunnel. Routes that aren't reject routes, or don't hold it, don't.
func TestRefusalIsAttributedToItsTunnel(t *testing.T) {
	owned := []domain.ManagedRoute{
		{Route: domain.Route{DstCIDR: "9.0.0.0/8", Family: domain.FamilyV4, Reject: true}, ProfileID: "tunnel:wide"},
		{Route: domain.Route{DstCIDR: "9.9.9.0/24", Family: domain.FamilyV4, Reject: true}, ProfileID: "tunnel:con3"},
		{Route: domain.Route{DstCIDR: "9.9.9.9/32", Gateway: "192.168.1.1", Family: domain.FamilyV4}, ProfileID: "p1"},
	}
	if got := rejectedBy(netip.MustParseAddr("9.9.9.9"), owned); got != "tunnel:con3" {
		t.Errorf("rejectedBy = %q", got)
	}
	if got := rejectedBy(netip.MustParseAddr("8.8.8.8"), owned); got != "" {
		t.Errorf("rejectedBy(8.8.8.8) = %q", got)
	}
	d := domain.RouteDecision{Rejected: true, Profile: "tunnel:con3"}
	markTunnel(&d, []domain.TunnelStatus{{Name: "con3", Type: domain.TunnelWireGuard, State: domain.TunnelReconnecting}})
	if d.Tunnel != "con3" || d.TunnelType != domain.TunnelWireGuard {
		t.Errorf("marked = %+v", d)
	}
	// A refusal isn't a live tunnel's interface match.
	d = domain.RouteDecision{Rejected: true, Iface: "utun8"}
	markTunnel(&d, []domain.TunnelStatus{{Name: "con3", State: domain.TunnelConnected, Iface: "utun8"}})
	if d.Tunnel != "" {
		t.Errorf("an untagged refusal was taken for a live tunnel: %+v", d)
	}
}

// The doctor warns about a tunnel that's down and blocking — how many of
// its destinations are refused, and which aren't yet — and says how to stop
// it; a failed one's check says so beside its error.
func TestDoctorReportsABlockingTunnel(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	in := routing.TunnelInput{Name: "con3", Block: true, Routes: []string{"9.9.9.9", "10.20.0.0/24"}}
	svc.SetTunnels(func() []routing.TunnelInput { return []routing.TunnelInput{in} }, func() []domain.TunnelStatus {
		return []domain.TunnelStatus{{Name: "con3", Routes: in.Routes, State: domain.TunnelReconnecting, WhenDown: domain.TunnelBlock, Blocking: true}}
	})
	desired, _, _, err := svc.DesiredTunnelsOnly(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range desired {
		if d.DstCIDR == "9.9.9.9/32" {
			if err := svc.Provider().AddRoute(ctx, d); err != nil {
				t.Fatal(err)
			}
		}
	}
	c := tunnelCheck(t, svc, "con3")
	if c.Status != domain.CheckWarn || !strings.Contains(c.Detail, "1 destination(s) blocked") ||
		!strings.Contains(c.Detail, "not blocked yet") || !strings.Contains(c.Detail, "10.20.0.0/24") ||
		!strings.Contains(c.Fix, "tunnel down con3") {
		t.Errorf("check = %+v", c)
	}

	svc.tunnelStatus = func() []domain.TunnelStatus {
		return []domain.TunnelStatus{{Name: "con3", Routes: in.Routes, State: domain.TunnelFailed, LastError: "gave up", Blocking: true}}
	}
	if c := tunnelCheck(t, svc, "con3"); c.Status != domain.CheckFail || !strings.Contains(c.Detail, "gave up; 1 destination(s) blocked") ||
		!strings.Contains(c.Fix, "to stop blocking") {
		t.Errorf("failed check = %+v", c)
	}
}
