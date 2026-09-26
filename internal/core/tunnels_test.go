package core

import (
	"context"
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
