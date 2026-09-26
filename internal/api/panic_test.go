package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider/fake"
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
