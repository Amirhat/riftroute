package netmon

import (
	"context"
	"github.com/Amirhat/riftroute/internal/domain"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/provider/fake"
)

func TestPollerDetectsVPNDown(t *testing.T) {
	prov := fake.New() // scenario: VPN up (utun3 default)
	p := NewPoller(prov, time.Second)
	ctx := context.Background()

	if ev := p.PollOnce(ctx); ev != nil {
		t.Fatalf("first poll should only baseline, emitted %v", ev)
	}
	// Bring the VPN down → default route returns to the physical gateway.
	prov.SetVPN(false)
	events := p.PollOnce(ctx)

	var sawVPNDown, sawDefaultChange bool
	for _, e := range events {
		switch e.Type {
		case EventVPNDown:
			sawVPNDown = true
		case EventDefaultRouteChanged:
			sawDefaultChange = true
		}
	}
	if !sawVPNDown {
		t.Fatalf("expected VPNDown event, got %+v", events)
	}
	if !sawDefaultChange {
		t.Fatalf("expected DefaultRouteChanged event, got %+v", events)
	}
}

func TestPollerDetectsVPNUp(t *testing.T) {
	prov := fake.New()
	prov.SetVPN(false) // start with VPN down
	p := NewPoller(prov, time.Second)
	ctx := context.Background()
	p.PollOnce(ctx) // baseline (VPN down)

	prov.SetVPN(true)
	events := p.PollOnce(ctx)
	var sawUp bool
	for _, e := range events {
		if e.Type == EventVPNUp {
			sawUp = true
		}
	}
	if !sawUp {
		t.Fatalf("expected VPNUp event, got %+v", events)
	}
}

func TestPollerQuietWhenStable(t *testing.T) {
	prov := fake.New()
	p := NewPoller(prov, time.Second)
	ctx := context.Background()
	p.PollOnce(ctx)
	if ev := p.PollOnce(ctx); len(ev) != 0 {
		t.Fatalf("stable network should emit nothing, got %+v", ev)
	}
}

// With a VPN's default winning, the physical default's next hop is watched
// too: a new Wi-Fi network (or Ethernet beside it) changes it while the
// winning default stays — and the exclude routes must follow.
func TestDefaultKeysWatchThePhysicalGatewayBehindAVPN(t *testing.T) {
	table := func(phys string) []domain.Route {
		return []domain.Route{
			{DstCIDR: "0.0.0.0/0", Iface: "utun4", Owner: domain.OwnerVPN}, // wins, on-link
			{DstCIDR: "0.0.0.0/0", Gateway: phys, Iface: "en0", Owner: domain.OwnerSystem},
			{DstCIDR: "0.0.0.0/0", Gateway: "10.0.0.1", Iface: "en9", Owner: domain.OwnerSystem, Table: "5252"}, // not main
			{DstCIDR: "9.9.9.0/24", Gateway: phys, Iface: "en0", Owner: domain.OwnerRiftRoute},
		}
	}
	def1, phys1 := defaultKeysFrom(table("192.168.88.1"), domain.FamilyV4)
	def2, phys2 := defaultKeysFrom(table("192.168.0.1"), domain.FamilyV4)
	if def1 != def2 || def1 != "|utun4|vpn" {
		t.Fatalf("the winning default's key: %q, %q", def1, def2)
	}
	if phys1 != "192.168.88.1|en0" || phys2 != "192.168.0.1|en0" {
		t.Fatalf("physical keys %q, %q", phys1, phys2)
	}
	if _, phys := defaultKeysFrom(table("192.168.88.1")[:1], domain.FamilyV4); phys != "" {
		t.Fatalf("a VPN's own default counted as physical: %q", phys)
	}
}
