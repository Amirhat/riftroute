package routing

import (
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

func mr(cidr, gw, iface, profile string) domain.ManagedRoute {
	return domain.ManagedRoute{
		Route:     domain.Route{DstCIDR: cidr, Gateway: gw, Iface: iface, Family: domain.FamilyV4, Owner: domain.OwnerRiftRoute},
		ProfileID: profile,
	}
}

func TestDetectConflictsDuplicate(t *testing.T) {
	cs := DetectConflicts([]domain.ManagedRoute{
		mr("10.0.0.0/8", "192.168.1.1", "en0", "p1"),
		mr("10.0.0.0/8", "10.6.0.1", "wg0", "p2"),
	})
	if len(cs) != 1 || cs[0].Kind != "duplicate" {
		t.Fatalf("expected one duplicate conflict, got %+v", cs)
	}
}

func TestDetectConflictsShadowed(t *testing.T) {
	cs := DetectConflicts([]domain.ManagedRoute{
		mr("10.0.0.0/8", "192.168.1.1", "en0", "p1"),
		mr("10.1.0.0/16", "10.6.0.1", "wg0", "p2"),
	})
	if len(cs) != 1 || cs[0].Kind != "shadowed" {
		t.Fatalf("expected one shadowed conflict, got %+v", cs)
	}
}

func TestNoConflictWhenSameNextHop(t *testing.T) {
	cs := DetectConflicts([]domain.ManagedRoute{
		mr("10.0.0.0/8", "192.168.1.1", "en0", "p1"),
		mr("10.1.0.0/16", "192.168.1.1", "en0", "p2"), // same next hop → harmless
	})
	if len(cs) != 0 {
		t.Fatalf("same next hop should not conflict, got %+v", cs)
	}
}

func TestNoConflictWhenDisjoint(t *testing.T) {
	cs := DetectConflicts([]domain.ManagedRoute{
		mr("10.0.0.0/8", "192.168.1.1", "en0", "p1"),
		mr("172.16.0.0/12", "10.6.0.1", "wg0", "p2"),
	})
	if len(cs) != 0 {
		t.Fatalf("disjoint prefixes should not conflict, got %+v", cs)
	}
}
