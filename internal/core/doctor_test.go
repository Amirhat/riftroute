package core

import (
	"context"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/store"
)

func newSvc(t *testing.T) *Service {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(fake.New(), st, "test")
}

func TestDoctorHealthyOnFake(t *testing.T) {
	rep := newSvc(t).Doctor(context.Background())
	if rep.Fail != 0 || !rep.OK {
		t.Fatalf("fake scenario should be healthy: %+v", rep)
	}
	names := map[string]domain.CheckStatus{}
	for _, c := range rep.Checks {
		names[c.Name] = c.Status
	}
	for _, want := range []string{"daemon", "gateway", "default-route", "dns", "drift", "conflicts"} {
		if _, ok := names[want]; !ok {
			t.Fatalf("missing check %q in %+v", want, names)
		}
	}
	if names["gateway"] != domain.CheckPass {
		t.Fatalf("gateway should pass, got %s", names["gateway"])
	}
}

func TestLeaksEmptyOnFakeScenario(t *testing.T) {
	// The fake's DNS (10.8.0.1) and default both egress the tunnel, so no leak.
	if lk := newSvc(t).Leaks(context.Background()); len(lk) != 0 {
		t.Fatalf("expected no leaks on the fake scenario, got %+v", lk)
	}
}
