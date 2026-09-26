package core

import (
	"context"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
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
