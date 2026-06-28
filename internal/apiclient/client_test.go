package apiclient

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/api"
	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/store"
)

// serveTest spins up the real API server over a real UDS and returns a client
// pointed at it. Exercises the full transport, including peer-cred (same user).
func serveTest(t *testing.T) (*Client, *api.Server, *store.Store) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "rr.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	prov := fake.New()
	svc := core.New(prov, st, "test")
	proto := safety.NewProtocol(prov, st, safety.RealClock{}, nil, "fake", nil)
	srv := api.NewServer(svc, st, proto, uint32(os.Getuid()), "test", nil)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		_ = st.Close()
	})
	return New(sock), srv, st
}

func TestClientReadRoundTrip(t *testing.T) {
	c, _, _ := serveTest(t)
	ctx := context.Background()

	ver, err := c.Ping(ctx)
	if err != nil || ver != "test" {
		t.Fatalf("ping: ver=%q err=%v", ver, err)
	}
	st, err := c.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Health.Provider != "fake" || !st.VPN.Active {
		t.Fatalf("unexpected state: %+v", st.Health)
	}
	routes, err := c.Routes(ctx, domain.FamilyV4, domain.OwnerVPN)
	if err != nil || len(routes) == 0 {
		t.Fatalf("routes: %v len=%d", err, len(routes))
	}
	ex, err := c.Explain(ctx, "192.168.1.10")
	if err != nil {
		t.Fatal(err)
	}
	if ex.Kernel.Iface != "en0" || ex.Kernel.ViaVPN {
		t.Fatalf("explain LAN should be direct via en0: %+v", ex.Kernel)
	}
}

func TestClientApplyConfirmPanic(t *testing.T) {
	c, _, st := serveTest(t)
	ctx := context.Background()

	// Seed an enabled exclude profile so apply has something to install.
	if err := st.UpsertProfile(domain.Profile{
		ID: "p1", Name: "direct", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "9.9.9.0/24"}},
	}); err != nil {
		t.Fatal(err)
	}

	// dry-run first: plan should show one add, nothing installed.
	plan, diff, err := c.Plan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Ops) != 1 || diff.Adds != 1 {
		t.Fatalf("plan should add 1 route, got ops=%d adds=%d", len(plan.Ops), diff.Adds)
	}

	// apply (non-interactive), then confirm to resolve promptly.
	res, err := c.Apply(ctx, ApplyOptions{Yes: true})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Status != domain.TxPending || res.TxID == "" {
		t.Fatalf("apply result: %+v", res)
	}
	managed, _ := c.Routes(ctx, domain.FamilyV4, domain.OwnerRiftRoute)
	if len(managed) != 1 || managed[0].DstCIDR != "9.9.9.0/24" {
		t.Fatalf("expected the bypass route installed, got %+v", managed)
	}
	if result, err := c.Confirm(ctx, res.TxID); err != nil || result != domain.TxCommitted {
		t.Fatalf("confirm: result=%s err=%v", result, err)
	}

	// panic removes it.
	if err := c.Panic(ctx); err != nil {
		t.Fatal(err)
	}
	managed, _ = c.Routes(ctx, domain.FamilyV4, domain.OwnerRiftRoute)
	if len(managed) != 0 {
		t.Fatalf("panic should remove managed routes, got %+v", managed)
	}
}

func TestClientUnreachable(t *testing.T) {
	c := New(filepath.Join(t.TempDir(), "nonexistent.sock"))
	_, err := c.Ping(context.Background())
	if !errors.Is(err, ErrDaemonUnreachable) {
		t.Fatalf("expected ErrDaemonUnreachable, got %v", err)
	}
}

func TestClientEventsStream(t *testing.T) {
	c, srv, _ := serveTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	got := make(chan domain.EventType, 8)
	go func() {
		_ = c.Events(ctx, func(ev domain.Event) {
			select {
			case got <- ev.Type:
			default:
			}
		})
	}()

	// Give the stream a moment to connect, then push a state event.
	deadline := time.After(2 * time.Second)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	var sawState bool
	for !sawState {
		select {
		case <-deadline:
			t.Fatal("did not receive a state event in time")
		case <-tick.C:
			srv.BroadcastState(context.Background())
		case et := <-got:
			if et == domain.EventState {
				sawState = true
			}
		}
	}
}
