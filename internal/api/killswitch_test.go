package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/killswitch"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/store"
)

func newKillSwitchServer(t *testing.T, ks killswitch.Manager) (*Server, *httptest.Server, *fake.Provider) {
	t.Helper()
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
	srv.SetKillSwitch(ks)
	h := srv.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), peerKey{}, peerInfo{uid: 0})))
	}))
	t.Cleanup(ts.Close)
	return srv, ts, prov
}

func post(t *testing.T, url, body string) {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: status %d", url, resp.StatusCode)
	}
}

// Tunnels are never guarded, so a VPN dropping and coming back (on any
// interface) needs no re-render at all — only the physical side matters.
func TestKillSwitchIgnoresTunnelChurn(t *testing.T) {
	ks := &killswitch.Fake{}
	srv, ts, prov := newKillSwitchServer(t, ks)
	ctx := context.Background()

	post(t, ts.URL+"/killswitch", `{"enabled":true}`)
	if got := ks.Last().PhysIfaces; !slices.Equal(got, []string{"en0"}) || ks.Enables != 1 {
		t.Fatalf("enable: guarding %v, enables=%d", got, ks.Enables)
	}
	prov.SetVPN(false)
	srv.SyncKillSwitch(ctx)
	prov.SetVPN(true)
	srv.SyncKillSwitch(ctx)
	if ks.Enables != 1 {
		t.Fatalf("tunnel churn reloaded the rules %d times", ks.Enables-1)
	}

	post(t, ts.URL+"/killswitch", `{"enabled":false}`)
	srv.SyncKillSwitch(ctx)
	if on, _ := ks.Enabled(ctx); on {
		t.Fatal("a kill switch turned off must stay off")
	}
}

// Panic = back to the baseline: the kill switch goes off too, and stays off.
func TestPanicTurnsKillSwitchOff(t *testing.T) {
	ks := &killswitch.Fake{}
	srv, ts, _ := newKillSwitchServer(t, ks)
	post(t, ts.URL+"/killswitch", `{"enabled":true}`)
	post(t, ts.URL+"/panic", ``)
	if on, _ := ks.Enabled(context.Background()); on {
		t.Fatal("panic left the kill switch on")
	}
	if v, _, _ := srv.store.GetSetting(killSwitchKey); v != "false" {
		t.Fatalf("panic must record the kill switch as off (restart would restore it), got %q", v)
	}
	srv.SyncKillSwitch(context.Background())
	if on, _ := ks.Enabled(context.Background()); on {
		t.Fatal("re-sync turned the kill switch back on after panic")
	}
}

// loadedNotEnforced is the pre-fix macOS state: rules in an anchor pf.conf
// never referenced, and no saved choice.
type loadedNotEnforced struct {
	killswitch.Fake
	disabled bool
}

func (l *loadedNotEnforced) Status(context.Context) killswitch.Status {
	return killswitch.Status{Loaded: !l.disabled, Effective: false}
}

func (l *loadedNotEnforced) Disable(ctx context.Context) error {
	l.disabled = true
	return l.Fake.Disable(ctx)
}

func TestInitKillSwitch(t *testing.T) {
	ctx := context.Background()

	// No saved choice + leftover rules → cleared, not suddenly enforced.
	legacy := &loadedNotEnforced{}
	srv, _, _ := newKillSwitchServer(t, legacy)
	srv.InitKillSwitch(ctx)
	if !legacy.disabled || legacy.Enables != 0 {
		t.Fatalf("leftover rules: disabled=%v enables=%d", legacy.disabled, legacy.Enables)
	}
	srv.SyncKillSwitch(ctx)
	if legacy.Enables != 0 {
		t.Fatal("cleared kill switch must not be re-synced on")
	}

	// Saved "on" (e.g. after a reboot emptied the kernel rules) → restored,
	// even though nothing is loaded — apps start before the VPN connects.
	fresh := &killswitch.Fake{}
	srv2, ts2, _ := newKillSwitchServer(t, fresh)
	post(t, ts2.URL+"/killswitch", `{"enabled":true}`)
	_ = fresh.Disable(ctx) // simulate the reboot wiping the kernel rules
	srv2.InitKillSwitch(ctx)
	if on, _ := fresh.Enabled(ctx); !on {
		t.Fatal("a kill switch the user turned on must come back after a restart/reboot")
	}
}

// Exclude-mode routes send chosen destinations around the VPN on purpose;
// the kill switch must let them through (or split tunneling breaks), and
// follow the set as profiles change.
func TestKillSwitchAllowsExcludeRoutes(t *testing.T) {
	ks := &killswitch.Fake{}
	srv, ts, _ := newKillSwitchServer(t, ks)
	post(t, ts.URL+"/killswitch", `{"enabled":true}`)
	if len(ks.Last().Bypass) != 0 {
		t.Fatalf("no exclude routes yet, bypass=%v", ks.Last().Bypass)
	}
	mr := domain.ManagedRoute{Route: domain.Route{DstCIDR: "185.10.75.0/24", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4, Owner: domain.OwnerRiftRoute}, ProfileID: "p1"}
	if err := srv.store.AddOwned(mr); err != nil {
		t.Fatal(err)
	}
	srv.SyncKillSwitch(context.Background())
	if !slices.Contains(ks.Last().Bypass, "185.10.75.0/24") {
		t.Fatalf("exclude route not allowed through the kill switch: %v", ks.Last().Bypass)
	}
}
