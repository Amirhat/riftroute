package safety_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/safety"
)

// checkingProvider checks the table before each managed delete, as the macOS
// provider does (route(8) deletes by destination alone), and counts the table
// reads that takes.
type checkingProvider struct {
	*fake.Provider
	reads atomic.Int32
}

func (p *checkingProvider) DelRoute(ctx context.Context, mr domain.ManagedRoute) error {
	if mr.ProfileID != "" {
		if _, err := provider.CachedRoutes(ctx, mr.Family, func(ctx context.Context, fam domain.Family) ([]domain.Route, error) {
			p.reads.Add(1)
			return p.Provider.ListRoutes(ctx, fam)
		}); err != nil {
			return err
		}
	}
	return p.Provider.DelRoute(ctx, mr)
}

func many(n int) []domain.ManagedRoute {
	var cidrs []string
	for i := range n {
		cidrs = append(cidrs, fmt.Sprintf("10.%d.0.0/16", i))
	}
	return desired(cidrs...)
}

// Withdrawing a big profile, and a panic, read the table once — not once per
// delete, which made them O(N²).
func TestDeletesShareOneTableRead(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	prov := &checkingProvider{Provider: h.prov}
	p := safety.NewProtocol(prov, h.st, h.clock, func() safety.Prober { return h.prober }, "fake", nil)
	t.Cleanup(p.ShutdownResolve)

	if res, err := p.Apply(ctx, many(20), nil, opts(false)); err != nil || res.Status != domain.TxPending {
		t.Fatalf("apply: %s %v", res.Status, err)
	}
	prov.reads.Store(0)
	if res, err := p.Apply(ctx, many(0), nil, opts(false)); err != nil || res.Status != domain.TxPending {
		t.Fatalf("withdrawal: %s %v", res.Status, err)
	}
	if n := prov.reads.Load(); n != 1 {
		t.Errorf("withdrawing 20 routes read the table %d times", n)
	}
	if h.prov.CountManaged() != 0 {
		t.Fatal("not withdrawn")
	}

	h.clock.Advance(30 * time.Second)
	if res, err := p.Apply(ctx, many(20), nil, opts(false)); err != nil || res.Status != domain.TxPending {
		t.Fatalf("apply: %s %v", res.Status, err)
	}
	prov.reads.Store(0)
	if err := p.Panic(ctx, domain.ActorUI); err != nil {
		t.Fatal(err)
	}
	if n := prov.reads.Load(); n != 1 {
		t.Errorf("a panic over 20 routes read the table %d times", n)
	}
}

// routesOutliveFlush is a provider whose flush leaves routes alone, as macOS's
// does (it empties the PF anchor; routes go by the ownership records).
type routesOutliveFlush struct{ *fake.Provider }

func (routesOutliveFlush) FlushOwned(context.Context) error { return nil }

// A panic can't forget a route it failed to remove: nothing would remove it
// later. The rest are forgotten, and the panic says what's left.
func TestPanicKeepsTheRecordsOfRoutesItCouldNotRemove(t *testing.T) {
	for _, c := range []struct {
		name     string
		flushed  bool // the provider's flush takes the route anyway (Linux)
		wantKept int
	}{
		{"routes outlive the flush", false, 1},
		{"the flush takes it", true, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			p := h.p
			if !c.flushed {
				p = safety.NewProtocol(routesOutliveFlush{h.prov}, h.st, h.clock, func() safety.Prober { return h.prober }, "fake", nil)
			}
			if res, err := p.Apply(ctx, desired("9.9.9.0/24", "8.8.8.0/24"), nil, opts(false)); err != nil || res.Status != domain.TxPending {
				t.Fatalf("apply: %s %v", res.Status, err)
			}
			h.prov.FailDelRoute("8.8.8.0/24", true)
			err := p.Panic(ctx, domain.ActorUI)
			owned, _ := h.st.ListOwned()
			if len(owned) != c.wantKept || (c.wantKept == 1 && owned[0].DstCIDR != "8.8.8.0/24") {
				t.Fatalf("owned after the panic = %+v, want %d kept", owned, c.wantKept)
			}
			if (err != nil) != (c.wantKept > 0) {
				t.Fatalf("panic: %v", err)
			}
			if c.flushed {
				return
			}
			h.prov.FailDelRoute("8.8.8.0/24", false) // the retry
			if err := p.Panic(ctx, domain.ActorUI); err != nil {
				t.Fatal(err)
			}
			if owned, _ := h.st.ListOwned(); len(owned) != 0 || h.prov.CountManaged() != 0 {
				t.Fatalf("after the retry: owned %+v, managed %d", owned, h.prov.CountManaged())
			}
		})
	}
}
