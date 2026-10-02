package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
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
