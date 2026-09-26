package api

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/reconcile"
	"github.com/Amirhat/riftroute/internal/routing"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/store"
)

// hookedProvider is the fake provider with a one-shot hook on its interface
// read. Deriving desired state reads the interfaces (the VPN's) after it has
// read the tunnels, so the hook lands a tunnel transition in the middle of it.
type hookedProvider struct {
	*fake.Provider
	mu       sync.Mutex
	onIfaces func()
}

func (p *hookedProvider) Interfaces(ctx context.Context) ([]domain.Iface, error) {
	p.mu.Lock()
	f := p.onIfaces
	p.onIfaces = nil
	p.mu.Unlock()
	if f != nil {
		f()
	}
	return p.Provider.Interfaces(ctx)
}

// A tunnel connecting while an API apply derives its desired set must not be
// undone by it: the handlers derive the set under the apply lock, so the
// tunnel's apply waits and lands after it — as the tunnel manager's would.
func TestAPIApplyDoesNotUndoATunnelApplyLandingMeanwhile(t *testing.T) {
	for _, c := range []struct{ name, path, body string }{
		{"apply", "/apply", `{"yes":true}`},
		{"profile toggle", "/profiles/direct/enable", ``},
		{"profile save", "/profiles?yes=1", `{"id":"p1","name":"direct","enabled":true,"mode":"exclude","gateway":"auto","rules":[{"type":"cidr","value":"9.9.9.0/24"}]}`},
	} {
		t.Run(c.name, func(t *testing.T) { apiApplyWithATunnelLanding(t, c.path, c.body) })
	}
}

func apiApplyWithATunnelLanding(t *testing.T, path, body string) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.UpsertProfile(domain.Profile{
		ID: "p1", Name: "direct", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "9.9.9.0/24"}},
	}); err != nil {
		t.Fatal(err)
	}
	prov := &hookedProvider{Provider: fake.New()}
	svc := core.New(prov, st, "test")
	proto := safety.NewProtocol(prov, st, safety.NewFakeClock(time.Unix(0, 0)), func() safety.Prober { return safety.NewFakeProber() }, "fake", nil)
	t.Cleanup(proto.ShutdownResolve)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rec := reconcile.New(svc, proto, log, 0, func() bool { return false })

	var mu sync.Mutex
	tunnels := []routing.TunnelInput{{Name: "infra", Routes: []string{"192.168.70.0/24"}}} // connecting
	svc.SetTunnels(func() []routing.TunnelInput {
		mu.Lock()
		defer mu.Unlock()
		return append([]routing.TunnelInput(nil), tunnels...)
	}, func() []domain.TunnelStatus { return nil })

	landed := make(chan struct{})
	prov.onIfaces = func() {
		go func() { // the tunnel connects, and the manager applies its routes
			defer close(landed)
			prov.SetTunnelIface("utun9", "10.99.0.2", true)
			mu.Lock()
			tunnels = []routing.TunnelInput{{Name: "infra", Iface: "utun9", Routes: []string{"192.168.70.0/24"}}}
			mu.Unlock()
			if err := rec.ApplyTunnels(context.Background()); err != nil {
				t.Error(err)
			}
		}()
		select {
		case <-landed:
		case <-time.After(300 * time.Millisecond): // held back by the apply lock
		}
	}

	srv := NewServer(svc, st, proto, 0, "test", log)
	h := srv.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), peerKey{}, peerInfo{uid: 0})))
	}))
	t.Cleanup(ts.Close)
	resp, err := http.Post(ts.URL+path, "application/json", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("apply: status %d", resp.StatusCode)
	}
	<-landed

	rs, err := prov.ListRoutes(context.Background(), domain.FamilyV4)
	if err != nil {
		t.Fatal(err)
	}
	via := map[string]string{}
	for _, r := range rs {
		if r.Owner == domain.OwnerRiftRoute {
			via[r.DstCIDR] = r.Iface
		}
	}
	if via["192.168.70.0/24"] != "utun9" {
		t.Errorf("the API apply undid the tunnel's routes: %v", via)
	}
	if via["9.9.9.0/24"] != "en0" {
		t.Errorf("the profile route wasn't applied: %v", via)
	}
}
