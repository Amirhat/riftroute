package safety_test

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/store"
)

// kernSim is a provider whose route table behaves like the real kernels',
// which the fake provider doesn't (it keeps any number of routes per
// destination):
//   - one route per family + table + destination;
//   - adding a destination that is already there fails with "File exists",
//     which the real providers report as success (AddRoute is idempotent), so
//     the route already there stays as it is;
//   - a delete matches by destination: macOS's route(8) ignores the gateway,
//     and Linux matches the destination plus RiftRoute's proto tag.
//
// Everything it doesn't model (rules, interfaces, DNS) comes from the fake.
type kernSim struct {
	*fake.Provider
	mu     sync.Mutex
	routes map[string]domain.Route
}

func newKernSim() *kernSim {
	return &kernSim{Provider: fake.New(), routes: map[string]domain.Route{}}
}

func simKey(r domain.Route) string { return string(r.Family) + "|" + r.Table + "|" + r.DstCIDR }

func (k *kernSim) AddRoute(_ context.Context, mr domain.ManagedRoute) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.routes[simKey(mr.Route)]; ok {
		return nil // "File exists" → reported as success; the existing route stays
	}
	r := mr.Route
	r.Owner, r.Profile = domain.OwnerRiftRoute, mr.ProfileID
	k.routes[simKey(r)] = r
	return nil
}

func (k *kernSim) DelRoute(_ context.Context, mr domain.ManagedRoute) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.routes, simKey(mr.Route)) // by destination; a missing route is success
	return nil
}

func (k *kernSim) ListRoutes(_ context.Context, fam domain.Family) ([]domain.Route, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []domain.Route
	for _, r := range k.routes {
		if r.Family == fam {
			out = append(out, r)
		}
	}
	return out, nil
}

// LookupRoute: every gateway in these tests is an on-link router.
func (k *kernSim) LookupRoute(_ context.Context, dst netip.Addr) (domain.RouteDecision, error) {
	return domain.RouteDecision{Target: dst.String(), Reachable: true}, nil
}

func (k *kernSim) FlushOwned(context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.routes = map[string]domain.Route{}
	return nil
}

// purge drops a route the way the kernel does when its interface goes away.
func (k *kernSim) purge(fam domain.Family, table, dst string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.routes, string(fam)+"|"+table+"|"+dst)
}

func (k *kernSim) route(fam domain.Family, table, dst string) (domain.Route, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	r, ok := k.routes[string(fam)+"|"+table+"|"+dst]
	return r, ok
}

type simHarness struct {
	p      *safety.Protocol
	k      *kernSim
	st     *store.Store
	clock  *safety.FakeClock
	prober *safety.FakeProber
}

func newSimHarness(t *testing.T) *simHarness {
	t.Helper()
	k := newKernSim()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	clock := safety.NewFakeClock(time.Unix(0, 0))
	prober := safety.NewFakeProber()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := safety.NewProtocol(k, st, clock, func() safety.Prober { return prober }, "fake", log)
	return &simHarness{p: p, k: k, st: st, clock: clock, prober: prober}
}

func via(dst, gw, iface, table string) domain.ManagedRoute {
	return domain.ManagedRoute{
		Route:     domain.Route{DstCIDR: dst, Gateway: gw, Iface: iface, Table: table, Family: domain.FamilyV4, Owner: domain.OwnerRiftRoute},
		ProfileID: "p1",
	}
}

func autoOpts(gw string) safety.Options {
	return safety.Options{
		Interactive:   false,
		Anchors:       []string{gw},
		K:             1,
		ProbeInterval: time.Second,
		GuardWindow:   30 * time.Second,
		Actor:         domain.ActorDaemon,
		PhysGW:        netip.MustParseAddr(gw),
	}
}

// applyAndCommit runs an auto-apply and lets its guard window pass cleanly.
func (h *simHarness) applyAndCommit(t *testing.T, desired []domain.ManagedRoute, gw string) {
	t.Helper()
	res, err := h.p.Apply(context.Background(), desired, nil, autoOpts(gw))
	if err != nil || res.Status != domain.TxPending {
		t.Fatalf("apply: status=%s err=%v violations=%v", res.Status, err, res.Violations)
	}
	h.clock.Advance(30 * time.Second)
	if got, _ := h.p.Wait(res.TxID); got != domain.TxCommitted {
		t.Fatalf("apply should commit, got %s", got)
	}
}

func (h *simHarness) wantRoute(t *testing.T, table, dst, gw, iface string) {
	t.Helper()
	r, ok := h.k.route(domain.FamilyV4, table, dst)
	if !ok {
		t.Fatalf("no route to %s (table %q) in the kernel: it was lost", dst, table)
	}
	if r.Gateway != gw || r.Iface != iface {
		t.Fatalf("route to %s goes via %s dev %s, want via %s dev %s", dst, r.Gateway, r.Iface, gw, iface)
	}
}

// Wi-Fi → Ethernet: an exclude route's next hop changes while the old route
// is still in the kernel. The new route must be what's left.
func TestNextHopChangeKeepsTheRoute(t *testing.T) {
	h := newSimHarness(t)
	h.applyAndCommit(t, []domain.ManagedRoute{via("9.9.9.0/24", "192.168.1.1", "en0", "")}, "192.168.1.1")
	h.wantRoute(t, "", "9.9.9.0/24", "192.168.1.1", "en0")

	h.applyAndCommit(t, []domain.ManagedRoute{via("9.9.9.0/24", "10.0.0.1", "en7", "")}, "10.0.0.1")
	h.wantRoute(t, "", "9.9.9.0/24", "10.0.0.1", "en7")
}

// The same, when the kernel already dropped the old route with its
// interface: deleting the old one must not take the new one with it.
func TestNextHopChangeAfterTheKernelPurgedTheOldRoute(t *testing.T) {
	h := newSimHarness(t)
	h.applyAndCommit(t, []domain.ManagedRoute{via("9.9.9.0/24", "192.168.1.1", "en0", "")}, "192.168.1.1")
	h.k.purge(domain.FamilyV4, "", "9.9.9.0/24") // Wi-Fi went down

	h.applyAndCommit(t, []domain.ManagedRoute{via("9.9.9.0/24", "10.0.0.1", "en7", "")}, "10.0.0.1")
	h.wantRoute(t, "", "9.9.9.0/24", "10.0.0.1", "en7")
}

// Model B: the include table's default follows the VPN's new gateway.
func TestNextHopChangeInATable(t *testing.T) {
	h := newSimHarness(t)
	h.applyAndCommit(t, []domain.ManagedRoute{via("0.0.0.0/0", "10.8.0.1", "tun0", "5252")}, "192.168.1.1")
	h.applyAndCommit(t, []domain.ManagedRoute{via("0.0.0.0/0", "10.9.0.1", "tun0", "5252")}, "192.168.1.1")
	h.wantRoute(t, "5252", "0.0.0.0/0", "10.9.0.1", "tun0")
}

// A next-hop change the guard rolls back must leave the old route in place.
func TestNextHopChangeRollbackRestoresTheOldRoute(t *testing.T) {
	h := newSimHarness(t)
	h.applyAndCommit(t, []domain.ManagedRoute{via("9.9.9.0/24", "192.168.1.1", "en0", "")}, "192.168.1.1")

	h.prober.SetReachable("10.0.0.1", false) // the new network's anchor is down
	res, err := h.p.Apply(context.Background(), []domain.ManagedRoute{via("9.9.9.0/24", "10.0.0.1", "en7", "")}, nil, autoOpts("10.0.0.1"))
	if err != nil || res.Status != domain.TxPending {
		t.Fatalf("apply: status=%s err=%v", res.Status, err)
	}
	h.clock.Advance(time.Second) // K=1 probe fails → rollback
	if got, _ := h.p.Wait(res.TxID); got != domain.TxRolledBack {
		t.Fatalf("want rolled back, got %s", got)
	}
	h.wantRoute(t, "", "9.9.9.0/24", "192.168.1.1", "en0")
	owned, _ := h.st.ListOwned()
	if len(owned) != 1 || owned[0].Gateway != "192.168.1.1" {
		t.Fatalf("ownership after rollback = %+v, want only the old route", owned)
	}
}

// An apply that fails part-way rolls a next-hop change back to the old route.
func TestNextHopChangeFailedApplyRestoresTheOldRoute(t *testing.T) {
	h := newSimHarness(t)
	h.applyAndCommit(t, []domain.ManagedRoute{via("9.9.9.0/24", "192.168.1.1", "en0", "")}, "192.168.1.1")

	failing := &failAfter{kernSim: h.k, dst: "8.8.8.0/24"}
	p := safety.NewProtocol(failing, h.st, h.clock, func() safety.Prober { return h.prober }, "fake", slog.New(slog.NewTextHandler(io.Discard, nil)))
	res, _ := p.Apply(context.Background(), []domain.ManagedRoute{
		via("9.9.9.0/24", "10.0.0.1", "en7", ""),
		via("8.8.8.0/24", "10.0.0.1", "en7", ""), // this add fails
	}, nil, autoOpts("10.0.0.1"))
	if res.Status != domain.TxFailed {
		t.Fatalf("want failed, got %s", res.Status)
	}
	h.wantRoute(t, "", "9.9.9.0/24", "192.168.1.1", "en0")
}

// failAfter makes adding one destination fail.
type failAfter struct {
	*kernSim
	dst string
}

func (f *failAfter) AddRoute(ctx context.Context, mr domain.ManagedRoute) error {
	if mr.Route.DstCIDR == f.dst {
		return context.DeadlineExceeded
	}
	return f.kernSim.AddRoute(ctx, mr)
}
