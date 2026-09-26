package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/reconcile"
	"github.com/Amirhat/riftroute/internal/routing"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/store"
)

// Panic must fire the teardown hook so the daemon restores side state the
// protocol doesn't own — the wildcard DNS learner and its resolver files.
// Without it a panic leaves /etc/resolver pointing at a stopped proxy.
func TestPanicFiresTeardownHook(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	prov := fake.New()
	svc := core.New(prov, st, "test")
	proto := safety.NewProtocol(prov, st, safety.RealClock{},
		func() safety.Prober { return safety.NewFakeProber() }, "fake", nil)
	srv := NewServer(svc, st, proto, uint32(0), "test", nil)

	fired := false
	srv.SetOnPanic(func(context.Context) { fired = true })

	h := srv.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), peerKey{}, peerInfo{uid: 0})
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/panic", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("panic status %d", resp.StatusCode)
	}
	if !fired {
		t.Fatal("onPanic teardown hook did not fire — resolver files would dangle at a stopped proxy")
	}
}

// routesOutliveFlush is the fake with macOS's flush: PF only, routes go by
// the ownership records.
type routesOutliveFlush struct{ *fake.Provider }

func (routesOutliveFlush) FlushOwned(context.Context) error { return nil }

// A route that won't delete fails the panic — it stays recorded for a retry —
// but the DNS teardown still runs: panic does all it can.
func TestPanicTearsDownEvenWhenARouteStays(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	f := fake.New()
	prov := routesOutliveFlush{f}
	svc := core.New(prov, st, "test")
	proto := safety.NewProtocol(prov, st, safety.RealClock{},
		func() safety.Prober { return safety.NewFakeProber() }, "fake", nil)
	t.Cleanup(proto.ShutdownResolve)
	srv := NewServer(svc, st, proto, uint32(0), "test", nil)
	route := []domain.ManagedRoute{{Route: domain.Route{DstCIDR: "9.9.9.0/24", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4}, ProfileID: "p1"}}
	if _, err := proto.Apply(context.Background(), route, nil, srv.buildOptions(applyReq{Yes: true}, netip.MustParseAddr("192.168.1.1"))); err != nil {
		t.Fatal(err)
	}
	f.FailDelRoute("9.9.9.0/24", true)
	fired := false
	srv.SetOnPanic(func(context.Context) { fired = true })

	h := srv.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), peerKey{}, peerInfo{uid: 0})))
	}))
	t.Cleanup(ts.Close)
	resp, err := http.Post(ts.URL+"/panic", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("panic status %d, want the route left reported", resp.StatusCode)
	}
	if !fired {
		t.Fatal("the DNS teardown didn't run")
	}
	if owned, _ := st.ListOwned(); len(owned) != 1 {
		t.Fatalf("owned = %+v, want the route that stayed", owned)
	}
}

// Panic takes the daemon's tunnels down BEFORE its flush: each tunnel going
// down re-applies the surviving tunnels' routes, which must be refused, not
// land after the flush. The post-flush teardown still runs after.
func TestPanicTakesTunnelsDownBeforeTheFlush(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	prov := fake.New()
	svc := core.New(prov, st, "test")
	proto := safety.NewProtocol(prov, st, safety.RealClock{},
		func() safety.Prober { return safety.NewFakeProber() }, "fake", nil)
	t.Cleanup(proto.ShutdownResolve)
	srv := NewServer(svc, st, proto, uint32(0), "test", nil)
	survivor := []domain.ManagedRoute{{Route: domain.Route{DstCIDR: "192.168.70.0/24", Iface: "utun9", Family: domain.FamilyV4}, ProfileID: "tunnel:b"}}
	opts := srv.buildOptions(applyReq{Yes: true}, netip.MustParseAddr("192.168.1.1"))
	if _, err := proto.Apply(context.Background(), survivor, nil, opts); err != nil {
		t.Fatal(err)
	}

	var order []string
	srv.SetBeforePanic(func(ctx context.Context) {
		order = append(order, "tunnels down")
		if prov.CountManaged() == 0 {
			t.Error("the flush ran before the tunnels went down")
		}
		if _, err := proto.Apply(ctx, survivor, nil, opts); !errors.Is(err, safety.ErrPanicking) {
			t.Errorf("a tunnel's re-apply during the panic: %v, want it refused", err)
		}
	})
	srv.SetOnPanic(func(context.Context) { order = append(order, "teardown") })

	h := srv.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), peerKey{}, peerInfo{uid: 0})))
	}))
	t.Cleanup(ts.Close)
	resp, err := http.Post(ts.URL+"/panic", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("panic status %d", resp.StatusCode)
	}
	if strings.Join(order, ", ") != "tunnels down, teardown" {
		t.Fatalf("order = %v", order)
	}
	if n := prov.CountManaged(); n != 0 {
		t.Fatalf("%d managed route(s) after the panic", n)
	}
}

// A change still on probation when the panic hits is committed by it: what
// it made yield to a tunnel is recorded then, and must be forgotten with the
// flush — the tunnel apply that follows the panic puts none of it back.
func TestPanicForgetsWhatAPendingChangeYielded(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	prov := fake.New()
	svc := core.New(prov, st, "test")
	var mu sync.Mutex
	live := []routing.TunnelInput{{Name: "infra", Iface: "utun9", Routes: []string{"10.70.0.0/16"}}}
	prov.SetTunnelIface("utun9", "10.99.0.2", true)
	svc.SetTunnels(func() []routing.TunnelInput {
		mu.Lock()
		defer mu.Unlock()
		return append([]routing.TunnelInput(nil), live...)
	}, func() []domain.TunnelStatus { return nil })
	proto := safety.NewProtocol(prov, st, safety.RealClock{},
		func() safety.Prober { return safety.NewFakeProber() }, "fake", nil)
	t.Cleanup(proto.ShutdownResolve)
	srv := NewServer(svc, st, proto, uint32(0), "test", nil)
	rec := reconcile.New(svc, proto, nil, 0, func() bool { return false })
	ctx := context.Background()
	if err := rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProfile(domain.Profile{ID: "p1", Name: "p1", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.70.9.0/24"}, {Type: domain.RuleCIDR, Value: "10.80.0.0/24"}}}); err != nil {
		t.Fatal(err)
	}
	if res, err := srv.applyProfiles(ctx, applyReq{Yes: true}, nil); err != nil || res.Status != domain.TxPending {
		t.Fatalf("apply: %v, %s", err, res.Status)
	}
	srv.SetBeforePanic(func(context.Context) { // the tunnels go down
		mu.Lock()
		live = nil
		mu.Unlock()
	})

	h := srv.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), peerKey{}, peerInfo{uid: 0})))
	}))
	t.Cleanup(ts.Close)
	resp, err := http.Post(ts.URL+"/panic", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("panic status %d", resp.StatusCode)
	}

	if err := rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	routes, err := prov.ListRoutes(ctx, domain.FamilyV4)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		if r.DstCIDR == "10.70.9.0/24" {
			t.Errorf("the panic was undone: %s is back via %s", r.DstCIDR, r.Iface)
		}
	}
}
