package store

import (
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSettingsRoundTrip(t *testing.T) {
	s := openTest(t)
	if _, ok, _ := s.GetSetting("theme"); ok {
		t.Fatal("expected missing setting")
	}
	if err := s.SetSetting("theme", "dark"); err != nil {
		t.Fatal(err)
	}
	v, ok, err := s.GetSetting("theme")
	if err != nil || !ok || v != "dark" {
		t.Fatalf("got %q ok=%v err=%v", v, ok, err)
	}
}

func TestProfilesCRUD(t *testing.T) {
	s := openTest(t)
	p := domain.Profile{
		ID: "p1", Name: "work-direct", Enabled: true, Mode: domain.ModeExclude,
		Gateway: "auto", Priority: 100,
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.0.0.0/8", Comment: "corp"}},
	}
	if err := s.UpsertProfile(p); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetProfile("work-direct")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "p1" || len(got.Rules) != 1 || got.Rules[0].Value != "10.0.0.0/8" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if err := s.SetProfileEnabled("work-direct", false); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetProfile("work-direct")
	if got.Enabled {
		t.Fatal("expected disabled")
	}
	list, err := s.ListProfiles()
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v len=%d", err, len(list))
	}
	if _, err := s.GetProfile("nope"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestAuditAppendAndList(t *testing.T) {
	s := openTest(t)
	for i := 0; i < 3; i++ {
		_, err := s.AppendAudit(domain.AuditEvent{
			TS: time.Now(), Actor: domain.ActorCLI, Action: "apply", Result: "committed",
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	evs, err := s.ListAudit(time.Time{}, 10)
	if err != nil || len(evs) != 3 {
		t.Fatalf("audit list: %v len=%d", err, len(evs))
	}
	if evs[0].ID <= evs[2].ID {
		t.Fatal("expected newest-first ordering")
	}
}

func TestOwnershipMap(t *testing.T) {
	s := openTest(t)
	mr := domain.ManagedRoute{
		Route:     domain.Route{DstCIDR: "8.8.8.0/24", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4},
		ProfileID: "p1", CreatedAt: time.Now(),
	}
	if err := s.AddOwned(mr); err != nil {
		t.Fatal(err)
	}
	owned, err := s.ListOwned()
	if err != nil || len(owned) != 1 {
		t.Fatalf("listowned: %v len=%d", err, len(owned))
	}
	if err := s.DelOwned(mr); err != nil {
		t.Fatal(err)
	}
	owned, _ = s.ListOwned()
	if len(owned) != 0 {
		t.Fatalf("expected empty after del, got %d", len(owned))
	}
}
