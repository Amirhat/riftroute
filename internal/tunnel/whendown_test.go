package tunnel

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/routing"
)

func blockSpec() domain.TunnelSpec {
	s := infraSpec()
	s.WhenDown = domain.TunnelBlock
	return s
}

// failingHarness is a harness whose server hangs up after every login, with
// a short backoff: the tunnel connects, reconnects, then fails.
func failingHarness(t *testing.T) *harness {
	t.Helper()
	d := holdBackoffMin
	holdBackoffMin = 10 * time.Millisecond
	t.Cleanup(func() { holdBackoffMin = d })
	return newHarness(t, func(f *FakeLauncher) { f.HangUp = true })
}

// blocked reports whether the inputs hold name blocked while it's down.
func blocked(in []routing.TunnelInput, name string) bool {
	i := slices.IndexFunc(in, func(t routing.TunnelInput) bool { return t.Name == name })
	return i >= 0 && in[i].Block && in[i].Iface == ""
}

// A block-mode tunnel's destinations are refused from Connect until it's up
// — through the attempts that fail, and after it gives up — until the user
// disconnects it. Its input carries its server (the config's literal
// address), so no reject route holds it. Until Connect, it isn't wanted and
// blocks nothing.
func TestBlockModeTunnelBlocksWhileWantedAndDown(t *testing.T) {
	h := failingHarness(t)
	ctx := context.Background()
	st, err := h.m.Save(ctx, blockSpec())
	if err != nil {
		t.Fatal(err)
	}
	if st.WhenDown != domain.TunnelBlock || st.Blocking {
		t.Fatalf("saved = %+v", st)
	}
	if in := h.m.Inputs(); len(in) != 0 {
		t.Fatalf("not wanted yet, but routed: %+v", in)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "blocking while it connects", func() bool { return blocked(h.m.Inputs(), "infra") })

	st = waitState(t, h.m, "infra", domain.TunnelFailed)
	if !st.Blocking {
		t.Fatalf("failed, but not blocking: %+v", st)
	}
	in := h.m.Inputs()
	if !blocked(in, "infra") || !slices.Contains(in[0].Servers, netip.MustParseAddr("198.51.100.7")) || len(in[0].Bypass) != 0 {
		t.Fatalf("inputs after the failure = %+v", in)
	}
	if !blocked(h.lastApply(), "infra") {
		t.Fatalf("the block wasn't applied: %+v", h.lastApply())
	}

	if err := h.m.Disconnect(ctx, "infra"); err != nil {
		t.Fatal(err)
	}
	if st, _ := h.m.Status("infra"); st.Blocking || st.State != domain.TunnelDisconnected || st.LastError != "" {
		t.Fatalf("after Disconnect = %+v", st)
	}
	if in := h.lastApply(); len(in) != 0 {
		t.Fatalf("Disconnect didn't lift the block: %+v", in)
	}
}

// Connected, a block-mode tunnel routes into its interface as any tunnel
// does (Block stays set: a v6 destination it can't carry is refused) and
// isn't blocking; a fallback tunnel's input never carries Block.
func TestBlockModeTunnelConnected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.m.Save(ctx, blockSpec()); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, h.m, "infra", domain.TunnelConnected)
	if st.Blocking {
		t.Fatalf("connected, but blocking: %+v", st)
	}
	if in := h.lastApply(); len(in) != 1 || in[0].Iface != "utun9" || !in[0].Block {
		t.Fatalf("inputs = %+v", in)
	}

	fallback := infraSpec()
	fallback.WhenDown = domain.TunnelFallback
	if _, err := h.m.Save(ctx, fallback); err != nil {
		t.Fatal(err)
	}
	if in := h.lastApply(); len(in) != 1 || in[0].Block {
		t.Fatalf("after switching to fallback: %+v", in)
	}
	if st, _ := h.m.Status("infra"); st.WhenDown != domain.TunnelFallback {
		t.Fatalf("when_down = %q", st.WhenDown)
	}
}

// A client that doesn't send when_down keeps the tunnel's; a value that
// isn't one is refused.
func TestSaveKeepsWhenDown(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.m.Save(ctx, blockSpec()); err != nil {
		t.Fatal(err)
	}
	if st, err := h.m.Save(ctx, infraSpec()); err != nil || st.WhenDown != domain.TunnelBlock {
		t.Fatalf("an old client's edit: %+v, %v", st, err)
	}
	bad := infraSpec()
	bad.WhenDown = "drop"
	if _, err := h.m.Save(ctx, bad); err == nil {
		t.Fatal("when_down drop was accepted")
	}
}

// A panic takes every tunnel down as a disconnect: nothing blocks after it,
// the failed ones included.
func TestPanicLiftsEveryBlock(t *testing.T) {
	h := failingHarness(t)
	ctx := context.Background()
	if _, err := h.m.Save(ctx, blockSpec()); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelFailed)
	h.m.DisconnectAll()
	if in := h.m.Inputs(); len(in) != 0 {
		t.Fatalf("still blocking after the panic: %+v", in)
	}
	if st, _ := h.m.Status("infra"); st.Blocking || st.State != domain.TunnelDisconnected {
		t.Fatalf("after the panic = %+v", st)
	}
}

// Changing a failed tunnel from block to fallback lifts its block at once.
func TestSaveReappliesAWantedTunnel(t *testing.T) {
	h := failingHarness(t)
	ctx := context.Background()
	if _, err := h.m.Save(ctx, blockSpec()); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelFailed)
	s := infraSpec()
	s.WhenDown = domain.TunnelFallback
	if _, err := h.m.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	if in := h.lastApply(); len(in) != 0 {
		t.Fatalf("the block stayed: %+v", in)
	}
}

// Restarting into an update keeps a block-mode tunnel's block while the
// daemon is gone — the last apply on the way down holds it — and the next
// run holds it from its first apply, before the tunnel is started again. A
// plain stop lifts it.
func TestBlockSurvivesAnUpdateRestart(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.m.Save(ctx, blockSpec()); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
	h.m.RememberForRestart(true)
	h.m.Shutdown()
	if !blocked(h.lastApply(), "infra") {
		t.Fatalf("the restart dropped the block: %+v", h.lastApply())
	}

	m2, err := New(Options{Dir: h.dir, Launcher: h.fl, Ifaces: h.m.o.Ifaces, Resolve: h.m.o.Resolve,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if !blocked(m2.Inputs(), "infra") {
		t.Fatalf("the next run's first apply would lift the block: %+v", m2.Inputs())
	}
	m2.StartAuto()
	waitState(t, m2, "infra", domain.TunnelConnected)

	m2.Shutdown() // a plain stop
	if in := m2.Inputs(); len(in) != 0 {
		t.Fatalf("a plain stop kept the block: %+v", in)
	}
}

// An auto-connect block-mode tunnel is wanted from the daemon's start, so
// it blocks before StartAuto brings it up.
func TestAutoConnectBlockTunnelIsWantedFromTheStart(t *testing.T) {
	h := newHarness(t)
	s := blockSpec()
	s.AutoConnect = true
	if _, err := h.m.Save(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	h.m.Shutdown()
	m2, err := New(Options{Dir: h.dir, Launcher: h.fl, Ifaces: h.m.o.Ifaces, Resolve: h.m.o.Resolve,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m2.Shutdown)
	if !blocked(m2.Inputs(), "infra") {
		t.Fatalf("inputs = %+v", m2.Inputs())
	}
	if st, _ := m2.Status("infra"); !st.Blocking {
		t.Fatalf("status = %+v", st)
	}
}

// Deleting a blocking tunnel lifts its block.
func TestDeleteLiftsTheBlock(t *testing.T) {
	h := failingHarness(t)
	ctx := context.Background()
	if _, err := h.m.Save(ctx, blockSpec()); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelFailed)
	if err := h.m.Delete(ctx, "infra"); err != nil {
		t.Fatal(err)
	}
	if in := h.lastApply(); len(in) != 0 {
		t.Fatalf("the deleted tunnel still blocks: %+v", in)
	}
}

// At startup a block-mode via-default tunnel whose server is a name is
// wanted before anyone knows the server's address, so the first apply may
// refuse the network that holds it. Its session applies again once the name
// resolves — before openvpn starts — so that network is left out and the
// connection can reach its server.
func TestBlockModeAppliesWithTheResolvedServerBeforeStarting(t *testing.T) {
	h := newHarness(t)
	s := domain.TunnelSpec{
		Name: "infra", Config: strings.Replace(pushProfile, "remote 198.51.100.7 1194 tcp", "remote vpn.example.net 1194 tcp", 1),
		Username: "alice", Password: "pw", Via: domain.TunnelViaDefault, AutoConnect: true,
		WhenDown: domain.TunnelBlock, Routes: []string{"192.0.2.0/24"},
	}
	if _, err := h.m.Save(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	h.m.Shutdown()

	var mu sync.Mutex
	var beforeStart [][]netip.Addr // the servers each apply saw before openvpn started
	var m2 *Manager
	// The name takes a moment to resolve, as it does: an apply requested at
	// Connect has run by then.
	resolve := func(ctx context.Context, host string) ([]netip.Addr, error) {
		time.Sleep(50 * time.Millisecond)
		return h.m.o.Resolve(ctx, host)
	}
	m2, err := New(Options{Dir: h.dir, Launcher: h.fl, Ifaces: h.m.o.Ifaces, Resolve: resolve,
		Apply: func(context.Context) error {
			if h.fl.Running() == 0 {
				for _, in := range m2.Inputs() {
					mu.Lock()
					beforeStart = append(beforeStart, in.Servers)
					mu.Unlock()
				}
			}
			return nil
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m2.Shutdown)
	if in := m2.Inputs(); len(in) != 1 || !in[0].Block || len(in[0].Servers) != 0 {
		t.Fatalf("at start = %+v", in)
	}
	m2.StartAuto()
	waitState(t, m2, "infra", domain.TunnelConnected)
	mu.Lock()
	defer mu.Unlock()
	if len(beforeStart) == 0 || !slices.Contains(beforeStart[len(beforeStart)-1], netip.MustParseAddr("192.0.2.44")) {
		t.Fatalf("the last apply before openvpn started didn't know the server: %v", beforeStart)
	}
}

// Restarting into a rollback withdraws every block on the way down — the
// previous version may not know reject routes, and would leave them owned
// by nothing — but still brings the connected tunnels back.
func TestRollbackRestartWithdrawsTheBlocks(t *testing.T) {
	h := failingHarness(t)
	ctx := context.Background()
	if _, err := h.m.Save(ctx, blockSpec()); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelFailed) // blocking
	h.m.RememberForRestart(false)
	h.m.Shutdown()
	if in := h.lastApply(); len(in) != 0 {
		t.Fatalf("a rollback kept the block: %+v", in)
	}
	m2, err := New(Options{Dir: h.dir, Launcher: h.fl, Ifaces: h.m.o.Ifaces, Resolve: h.m.o.Resolve,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m2.Shutdown)
	if in := m2.Inputs(); len(in) != 0 {
		t.Fatalf("a failed tunnel was resumed after a rollback: %+v", in)
	}
}

// ...and a connected block-mode tunnel is still brought back after it.
func TestRollbackRestartResumesConnectedTunnels(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.m.Save(ctx, blockSpec()); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
	h.m.RememberForRestart(false)
	h.m.Shutdown()
	if in := h.lastApply(); len(in) != 0 {
		t.Fatalf("a rollback kept the block: %+v", in)
	}
	m2, err := New(Options{Dir: h.dir, Launcher: h.fl, Ifaces: h.m.o.Ifaces, Resolve: h.m.o.Resolve,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m2.Shutdown)
	m2.StartAuto()
	waitState(t, m2, "infra", domain.TunnelConnected)
}
