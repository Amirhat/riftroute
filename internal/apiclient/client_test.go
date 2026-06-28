package apiclient

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/api"
	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/store"
)

// serveTest spins up the real API server over a real UDS and returns a client
// pointed at it. Exercises the full transport, including peer-cred (same user).
func serveTest(t *testing.T) (*Client, *api.Server) {
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
	svc := core.New(fake.New(), st, "test")
	srv := api.NewServer(svc, st, 0, "test", nil)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		_ = st.Close()
	})
	return New(sock), srv
}

func TestClientReadRoundTrip(t *testing.T) {
	c, _ := serveTest(t)
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

func TestClientUnreachable(t *testing.T) {
	c := New(filepath.Join(t.TempDir(), "nonexistent.sock"))
	_, err := c.Ping(context.Background())
	if !errors.Is(err, ErrDaemonUnreachable) {
		t.Fatalf("expected ErrDaemonUnreachable, got %v", err)
	}
}

func TestClientEventsStream(t *testing.T) {
	c, srv := serveTest(t)
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
