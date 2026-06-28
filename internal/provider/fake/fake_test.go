package fake

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

func TestLookupRouteLPM(t *testing.T) {
	p := New()
	ctx := context.Background()

	// 8.8.8.8 has no specific route -> default via VPN (utun3).
	dec, err := p.LookupRoute(ctx, netip.MustParseAddr("8.8.8.8"))
	if err != nil {
		t.Fatal(err)
	}
	if dec.MatchedCIDR != "0.0.0.0/0" || dec.Iface != "utun3" || !dec.ViaVPN {
		t.Fatalf("8.8.8.8 should match default via VPN, got %+v", dec)
	}

	// 192.168.1.10 matches the more-specific on-link LAN route on en0.
	dec, err = p.LookupRoute(ctx, netip.MustParseAddr("192.168.1.10"))
	if err != nil {
		t.Fatal(err)
	}
	if dec.MatchedCIDR != "192.168.1.0/24" || dec.Iface != "en0" || dec.ViaVPN {
		t.Fatalf("192.168.1.10 should match LAN on en0 direct, got %+v", dec)
	}
}

func TestAddRouteShiftsDecision(t *testing.T) {
	p := New()
	ctx := context.Background()

	mr := domain.ManagedRoute{
		Route:     domain.Route{DstCIDR: "8.8.8.0/24", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4},
		ProfileID: "google-direct",
		CreatedAt: time.Unix(0, 0),
	}
	if err := p.AddRoute(ctx, mr); err != nil {
		t.Fatal(err)
	}

	dec, err := p.LookupRoute(ctx, netip.MustParseAddr("8.8.8.8"))
	if err != nil {
		t.Fatal(err)
	}
	if dec.MatchedCIDR != "8.8.8.0/24" || dec.Iface != "en0" || dec.ViaVPN {
		t.Fatalf("after bypass, 8.8.8.8 should go direct via en0, got %+v", dec)
	}
	if dec.Owner != domain.OwnerRiftRoute || dec.Profile != "google-direct" {
		t.Fatalf("managed route should be owned by riftroute/profile, got %+v", dec)
	}
}

func TestDelRouteOwnershipInvariant(t *testing.T) {
	p := New()
	ctx := context.Background()

	// Deleting a route we never added must be refused (ownership invariant).
	foreign := domain.ManagedRoute{Route: domain.Route{DstCIDR: "192.168.1.0/24", Iface: "en0", Family: domain.FamilyV4}}
	if err := p.DelRoute(ctx, foreign); err == nil {
		t.Fatal("expected refusal deleting an unowned route")
	}

	// A route we added can be deleted.
	mr := domain.ManagedRoute{Route: domain.Route{DstCIDR: "1.1.1.0/24", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4}}
	if err := p.AddRoute(ctx, mr); err != nil {
		t.Fatal(err)
	}
	if err := p.DelRoute(ctx, mr); err != nil {
		t.Fatalf("deleting an owned route should succeed: %v", err)
	}
}

func TestFlushOwnedLeavesForeignRoutes(t *testing.T) {
	p := New()
	ctx := context.Background()

	before, _ := p.ListRoutes(ctx, domain.FamilyV4)
	mr := domain.ManagedRoute{Route: domain.Route{DstCIDR: "9.9.9.0/24", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4}}
	if err := p.AddRoute(ctx, mr); err != nil {
		t.Fatal(err)
	}
	if err := p.FlushOwned(ctx); err != nil {
		t.Fatal(err)
	}
	after, _ := p.ListRoutes(ctx, domain.FamilyV4)
	if len(after) != len(before) {
		t.Fatalf("flush should restore exactly the foreign routes: before=%d after=%d", len(before), len(after))
	}
	for _, r := range after {
		if r.Owner == domain.OwnerRiftRoute {
			t.Fatalf("flush left a managed route: %+v", r)
		}
	}
}
