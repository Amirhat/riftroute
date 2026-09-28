package reconcile_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/tunnel"
)

const loginProfile = "client\ndev tun\nremote 198.51.100.7 1194 udp\nauth-user-pass\n<ca>\nCA\n</ca>\n"

// withManager wires a real tunnel manager (openvpn is the fake launcher,
// speaking the real management protocol) into the harness: its applies go
// through the reconciler and the Apply Protocol, lock and all.
func (h *tunnelHarness) withManager(t *testing.T) *tunnel.Manager {
	t.Helper()
	dir, err := os.MkdirTemp("", "rr") // short: unix socket paths cap at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	m, err := tunnel.New(tunnel.Options{
		Dir: filepath.Join(dir, "tunnels"),
		Launcher: &tunnel.FakeLauncher{
			OnUp: func(iface, ip string) { h.prov.SetTunnelIface(iface, ip, true) },
			OnDown: func(iface, ip string) {
				h.prov.SetTunnelIface(iface, ip, false)
				h.prov.PurgeIface(iface) // its routes go with it
			},
		},
		Ifaces: h.prov.Interfaces,
		Apply:  h.rec.ApplyTunnels,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.svc.SetTunnels(m.Inputs, m.List)
	return m
}

func (h *tunnelHarness) waitKernel(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting: %s (kernel %v)", what, h.kernel(t))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// restartUnderUpdater is the daemon's way down into a restart the updater
// asked for: the updater holds the apply lock (TryQuiesce) until the
// process exits, and lends it to the tunnels' last applies.
func (h *tunnelHarness) restartUnderUpdater(t *testing.T, m *tunnel.Manager, rollback bool) time.Duration {
	t.Helper()
	var release func()
	h.waitKernel(t, "a quiet moment (the manager may still be applying)", func() bool {
		var ok bool
		release, ok, _ = h.proto.TryQuiesce(0)
		return ok
	})
	t.Cleanup(release)
	h.proto.LendQuiesce()
	start := time.Now()
	m.RememberForRestart(!rollback)
	m.Shutdown()
	return time.Since(start)
}

// A rollback withdraws a blocking tunnel's reject routes on the way down,
// under the updater's lock — the previous version may not know them — and
// doesn't stall the exit waiting for that lock.
func TestRollbackWithdrawsTheBlockUnderTheUpdatersLock(t *testing.T) {
	h := newTunnelHarness(t)
	m := h.withManager(t)
	ctx := context.Background()
	if _, err := m.Save(ctx, domain.TunnelSpec{Name: "con3", Config: loginProfile, Username: "alice", Password: "wrong",
		Routes: []string{"9.9.9.9"}, WhenDown: domain.TunnelBlock}); err != nil {
		t.Fatal(err)
	}
	if err := m.Connect("con3"); err != nil {
		t.Fatal(err)
	}
	h.waitKernel(t, "the failed tunnel's block", func() bool { return h.refused(t)["9.9.9.9/32"] })

	took := h.restartUnderUpdater(t, m, true)
	if r := h.refused(t); len(r) != 0 {
		t.Errorf("the rollback left the block: %v", r)
	}
	if o := h.ownedTunnelRoutes(t); len(o) != 0 {
		t.Errorf("still recorded: %+v", o)
	}
	if took > 3*time.Second {
		t.Errorf("the way down took %s: the withdrawal waited on the lock", took)
	}
}

// An update refuses a connected block-mode tunnel's destinations once it's
// stopped on the way down — recorded, so the next start keeps them until
// the tunnel is back — rather than letting them out while the daemon is gone.
func TestUpdateRestartBlocksAConnectedTunnelUnderTheUpdatersLock(t *testing.T) {
	h := newTunnelHarness(t)
	m := h.withManager(t)
	ctx := context.Background()
	if _, err := m.Save(ctx, domain.TunnelSpec{Name: "con3", Config: loginProfile, Username: "alice", Password: "pw",
		Routes: []string{"9.9.9.9"}, WhenDown: domain.TunnelBlock}); err != nil {
		t.Fatal(err)
	}
	if err := m.Connect("con3"); err != nil {
		t.Fatal(err)
	}
	h.waitKernel(t, "into the tunnel", func() bool { got := h.kernel(t)["9.9.9.9/32"]; return len(got) == 1 && got[0] == "utun9" })

	took := h.restartUnderUpdater(t, m, false)
	if !h.refused(t)["9.9.9.9/32"] {
		t.Errorf("the update let the destination out: kernel %v", h.kernel(t))
	}
	rec := false
	for _, o := range h.ownedTunnelRoutes(t) {
		rec = rec || (o.Reject && o.DstCIDR == "9.9.9.9/32")
	}
	if !rec {
		t.Errorf("the block isn't recorded for the next start: %+v", h.ownedTunnelRoutes(t))
	}
	if took > 3*time.Second {
		t.Errorf("the way down took %s: the apply waited on the lock", took)
	}
}
