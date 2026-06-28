package netmon

import (
	"context"
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
