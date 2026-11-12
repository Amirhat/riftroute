package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/routing"
)

// A profile route the ownership map holds but the kernel doesn't (another
// program removed it) is drift — missing, pending, and the doctor says so —
// not "in sync". One held by the Apply Protocol isn't pending: the doctor
// says another program keeps removing it.
func TestDriftSeesRoutesAnotherProgramRemoved(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	if err := svc.Store().UpsertProfile(domain.Profile{ID: "p1", Name: "direct", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "9.9.9.0/24"}}}); err != nil {
		t.Fatal(err)
	}
	desired, _, _, err := svc.DesiredManaged(ctx)
	if err != nil || len(desired) != 1 {
		t.Fatalf("desired = %+v, %v", desired, err)
	}
	if err := svc.Store().AddOwned(desired[0]); err != nil { // owned, not in the kernel
		t.Fatal(err)
	}
	drift := func() (domain.DriftStatus, domain.DoctorCheck) {
		st, err := svc.State(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range svc.Doctor(ctx).Checks {
			if c.Name == "drift" {
				return st.Drift, c
			}
		}
		t.Fatal("no drift check")
		return domain.DriftStatus{}, domain.DoctorCheck{}
	}
	if d, c := drift(); !d.Pending || d.Adds != 1 || d.Missing != 1 || svc.LiveMissing(ctx) != 1 || !strings.Contains(c.Detail, "gone from the kernel") {
		t.Fatalf("missing: drift %+v, check %+v", d, c)
	}

	svc.SetHeldRoutes(func() []domain.HeldRoute {
		return []domain.HeldRoute{{Route: desired[0].Route, Until: time.Now().Add(30 * time.Minute)}}
	})
	if d, c := drift(); d.Pending || d.Missing != 0 || len(d.Held) != 1 || svc.LiveMissing(ctx) != 0 ||
		c.Status != domain.CheckWarn || !strings.Contains(c.Detail, "keeps removing 9.9.9.0/24") {
		t.Fatalf("held: drift %+v, check %+v", d, c)
	}
}

// Another program's route to the destination: not missing (an apply can't
// put RiftRoute's beside it), but taken, and the doctor says so.
func TestDriftSeesADestinationAnotherProgramRoutes(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	if err := svc.Store().UpsertProfile(domain.Profile{ID: "p1", Name: "direct", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "9.9.9.0/24"}}}); err != nil {
		t.Fatal(err)
	}
	desired, _, _, err := svc.DesiredManaged(ctx)
	if err != nil || len(desired) != 1 {
		t.Fatalf("desired = %+v, %v", desired, err)
	}
	if err := svc.Store().AddOwned(desired[0]); err != nil {
		t.Fatal(err)
	}
	theirs := domain.ManagedRoute{Route: domain.Route{DstCIDR: "9.9.9.0/24", Iface: "utun3", Family: domain.FamilyV4, Owner: domain.OwnerVPN}}
	if err := svc.Provider().AddRoute(ctx, theirs); err != nil {
		t.Fatal(err)
	}
	st, err := svc.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Drift.Pending || st.Drift.Missing != 0 || len(st.Drift.Taken) != 1 || svc.LiveMissing(ctx) != 0 {
		t.Fatalf("drift %+v", st.Drift)
	}
	for _, c := range svc.Doctor(ctx).Checks {
		if c.Name == "drift" && (c.Status != domain.CheckWarn || !strings.Contains(c.Detail, "another program now routes 9.9.9.0/24")) {
			t.Fatalf("check %+v", c)
		}
	}
}

// A main VPN whose catch-all is the two /1 halves (OpenVPN's redirect-gateway
// def1) is the VPN as much as one with a default route; one of RiftRoute's
// own tunnels never is.
func TestResolveVPNTakesTheHalves(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	prov := svc.Provider()
	rs, _ := prov.ListRoutes(ctx, domain.FamilyV4)
	for _, r := range rs {
		if r.DstCIDR == "0.0.0.0/0" {
			_ = prov.DelRoute(ctx, domain.ManagedRoute{Route: r})
		}
	}
	if _, iface := svc.resolveVPN(ctx, domain.FamilyV4); iface != "" {
		t.Fatalf("a VPN without a catch-all: %q", iface)
	}
	for _, h := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := prov.AddRoute(ctx, domain.ManagedRoute{Route: domain.Route{DstCIDR: h, Gateway: "10.8.0.1", Iface: "utun3", Family: domain.FamilyV4, Owner: domain.OwnerVPN}}); err != nil {
			t.Fatal(err)
		}
	}
	if gw, iface := svc.resolveVPN(ctx, domain.FamilyV4); iface != "utun3" || gw.String() != "10.8.0.1" {
		t.Fatalf("halves: %v %q", gw, iface)
	}
	withTunnels(svc, routing.TunnelInput{Name: "mine", Iface: "utun3"}) // as if utun3 were RiftRoute's
	if _, iface := svc.resolveVPN(ctx, domain.FamilyV4); iface != "" {
		t.Fatalf("RiftRoute's own tunnel taken for the VPN: %q", iface)
	}
}

// A tunnel's own route that goes elsewhere — its server's pin, a full
// tunnel's keep-out — keeps traffic out of the tunnel; the lookup says so
// instead of "via tunnel".
func TestMarkTunnelTellsAPinFromARouteIntoIt(t *testing.T) {
	ts := []domain.TunnelStatus{{Name: "home", Iface: "utun9", State: domain.TunnelConnected}}
	pin := domain.RouteDecision{Reachable: true, Iface: "en0", Gateway: "192.168.1.1", Profile: "tunnel:home"}
	markTunnel(&pin, ts)
	if pin.Tunnel != "" || pin.KeptOutOf != "home" {
		t.Fatalf("pin: %+v", pin)
	}
	into := domain.RouteDecision{Reachable: true, Iface: "utun9", Profile: "tunnel:home"}
	markTunnel(&into, ts)
	if into.Tunnel != "home" || into.KeptOutOf != "" {
		t.Fatalf("into: %+v", into)
	}
	refused := domain.RouteDecision{Rejected: true, Profile: "tunnel:home"}
	markTunnel(&refused, []domain.TunnelStatus{{Name: "home"}})
	if refused.Tunnel != "home" {
		t.Fatalf("refused: %+v", refused)
	}
}
