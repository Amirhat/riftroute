package core

import (
	"context"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/routing"
)

// An include-mode app rule sends an app's traffic into the VPN before the
// routing table is consulted — to a connected tunnel's networks too. The
// doctor doesn't call that tunnel's routes working, and its status says what
// captures them.
func TestDoctorWarnsOfAppRulesCapturingATunnel(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	withTunnels(svc, routing.TunnelInput{Name: "infra", Iface: "utun6", Routes: []string{"192.168.70.0/24"}})
	desired, _, _, err := svc.DesiredTunnelsOnly(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range desired {
		if err := svc.Provider().AddRoute(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	if c := tunnelCheck(t, svc, "infra"); c.Status != domain.CheckPass {
		t.Fatalf("installed, nothing capturing it: %s %q", c.Status, c.Detail)
	}

	app := domain.ManagedRule{PolicyRule: domain.PolicyRule{Priority: routing.ModelBRulePrio, Selector: "from all fwmark " + routing.ModelBMark, Table: routing.ModelBTable, Family: domain.FamilyV4, Proto: "riftroute"}}
	if err := svc.Provider().AddRule(ctx, app); err != nil {
		t.Fatal(err)
	}
	c := tunnelCheck(t, svc, "infra")
	if c.Status != domain.CheckWarn || !strings.Contains(c.Detail, "fwmark") || !strings.Contains(c.Detail, "192.168.70.0/24") {
		t.Fatalf("an app rule captures it: %s %q", c.Status, c.Detail)
	}
	ts := svc.TunnelStatuses(ctx)
	if len(ts) != 1 || len(ts[0].Captured) != 1 || len(ts[0].Blocked) != 0 {
		t.Fatalf("status = %+v", ts)
	}
}
