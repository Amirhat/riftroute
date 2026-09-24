package reconcile_test

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/reconcile"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/store"
	"github.com/Amirhat/riftroute/internal/tunnel"
)

const tunnelProfile = "client\ndev tun\nremote 198.51.100.7 1194 tcp\nauth-user-pass\nredirect-gateway def1\n<ca>\nCA\n</ca>\n"

// Connecting a tunnel with auto-apply OFF installs exactly the tunnel's
// routes: a profile change staged for the user's review stays unapplied.
func TestTunnelConnectAppliesOnlyTunnelRoutes(t *testing.T) {
	prov := fake.New()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	// Enabled but never applied — what "auto-apply off" leaves staged.
	if err := st.UpsertProfile(domain.Profile{
		ID: "p1", Name: "staged", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "9.9.9.0/24"}},
	}); err != nil {
		t.Fatal(err)
	}
	svc := core.New(prov, st, "test")
	proto := safety.NewProtocol(prov, st, safety.NewFakeClock(time.Unix(0, 0)), func() safety.Prober { return safety.NewFakeProber() }, "fake", nil)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rec := reconcile.New(svc, proto, log, 0, func() bool { return false }) // auto-apply off

	m, err := tunnel.New(tunnel.Options{
		Dir: filepath.Join(t.TempDir(), "tunnels"),
		Launcher: &tunnel.FakeLauncher{
			Iface:  "utun9",
			OnUp:   func(iface, ip string) { prov.SetTunnelIface(iface, ip, true) },
			OnDown: func(iface, ip string) { prov.SetTunnelIface(iface, ip, false) },
		},
		Ifaces: prov.Interfaces,
		Apply:  rec.ApplyTunnels,
		Log:    log,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Shutdown)
	svc.SetTunnels(m.Inputs, m.List)

	ctx := context.Background()
	if _, err := m.Save(ctx, domain.TunnelSpec{
		Name: "infra", Config: tunnelProfile, Username: "u", Password: "p",
		Routes: []string{"192.168.70.0/24", "192.168.72.11"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for prov.CountManaged() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	routes, _ := prov.ListRoutes(ctx, domain.FamilyV4)
	has := map[string]domain.Route{}
	for _, r := range routes {
		if r.Owner == domain.OwnerRiftRoute {
			has[r.DstCIDR] = r
		}
	}
	for _, dst := range []string{"192.168.70.0/24", "192.168.72.11/32"} {
		if has[dst].Iface != "utun9" {
			t.Errorf("%s not routed into the tunnel: %+v", dst, has[dst])
		}
	}
	if has["198.51.100.7/32"].Iface != "en0" {
		t.Errorf("server not pinned to the physical path: %+v", has)
	}
	if _, ok := has["9.9.9.0/24"]; ok {
		t.Error("a staged profile change was applied by a tunnel connect")
	}

	// Disconnect withdraws exactly the tunnel's routes.
	if err := m.Disconnect(ctx, "infra"); err != nil {
		t.Fatal(err)
	}
	if n := prov.CountManaged(); n != 0 {
		t.Fatalf("%d managed routes left after disconnect", n)
	}
	// With the tunnel down, the desired set is still computable (no drift error).
	if s, _ := svc.State(ctx); s.Drift.Reason != "" {
		t.Fatalf("drift error with the tunnel down: %s", s.Drift.Reason)
	}
}
