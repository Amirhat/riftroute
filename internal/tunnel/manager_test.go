package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/routing"
)

type harness struct {
	m       *Manager
	dir     string
	mu      sync.Mutex
	ifaces  []domain.Iface
	applies [][]routing.TunnelInput
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{dir: filepath.Join(t.TempDir(), "tunnels")}
	fl := &FakeLauncher{
		OnUp: func(iface, ip string) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.ifaces = append(h.ifaces, domain.Iface{Name: iface, Up: true, Addrs: []string{ip + "/24"}, IsVPN: true})
		},
		OnDown: func(iface, _ string) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.ifaces = nil
		},
	}
	m, err := New(Options{
		Dir:      h.dir,
		Launcher: fl,
		Ifaces: func(context.Context) ([]domain.Iface, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			return append([]domain.Iface(nil), h.ifaces...), nil
		},
		Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("192.0.2.44")}, nil
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	m.o.Apply = func(context.Context) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.applies = append(h.applies, m.Inputs())
		return nil
	}
	t.Cleanup(m.Shutdown)
	h.m = m
	return h
}

func (h *harness) lastApply() []routing.TunnelInput {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.applies) == 0 {
		return nil
	}
	return h.applies[len(h.applies)-1]
}

func waitState(t *testing.T, m *Manager, name string, want domain.TunnelState) domain.TunnelStatus {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, _ := m.Status(name)
		if st.State == want {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("tunnel %s: state %s (%s), want %s", name, st.State, st.LastError, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func infraSpec() domain.TunnelSpec {
	return domain.TunnelSpec{
		Name: "infra", Config: pushProfile, Username: "alice", Password: "pw",
		Routes: []string{"192.168.70.0/24", "192.168.72.11", "192.168.72.12", "192.168.72.13"},
	}
}

func TestConnectRoutesOnlyListedDestinations(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	st, err := h.m.Save(ctx, infraSpec())
	if err != nil {
		t.Fatal(err)
	}
	if st.Via != domain.TunnelViaDirect || !st.NeedsAuth || !st.HasPassword || st.State != domain.TunnelDisconnected {
		t.Fatalf("saved status = %+v", st)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	st = waitState(t, h.m, "infra", domain.TunnelConnected)
	if st.Iface != "utun9" || st.LocalIP != "10.99.0.2" || st.Server != "198.51.100.7:1194" || st.Since == nil {
		t.Fatalf("connected status = %+v", st)
	}
	in := h.lastApply()
	if len(in) != 1 || in[0].Iface != "utun9" {
		t.Fatalf("apply inputs = %+v", in)
	}
	if got := strings.Join(in[0].Routes, ","); got != "192.168.70.0/24,192.168.72.11,192.168.72.12,192.168.72.13" {
		t.Errorf("routes = %s", got)
	}
	if len(in[0].Bypass) != 1 || in[0].Bypass[0].String() != "198.51.100.7" {
		t.Errorf("bypass = %v (via direct pins the server)", in[0].Bypass)
	}

	if err := h.m.Disconnect(ctx, "infra"); err != nil {
		t.Fatal(err)
	}
	st = waitState(t, h.m, "infra", domain.TunnelDisconnected)
	if st.LastError != "" || st.Iface != "" {
		t.Fatalf("after disconnect: %+v", st)
	}
	if in := h.lastApply(); len(in) != 0 {
		t.Fatalf("routes must be withdrawn on disconnect, last apply = %+v", in)
	}
	ents, _ := os.ReadDir(h.m.runDir)
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") { // the definition stays
			t.Errorf("runtime file left behind: %s", e.Name())
		}
	}
}

func TestWrongPasswordFails(t *testing.T) {
	h := newHarness(t)
	spec := infraSpec()
	spec.Password = "wrong"
	if _, err := h.m.Save(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, h.m, "infra", domain.TunnelFailed)
	if !strings.Contains(st.LastError, "rejected the username or password") {
		t.Fatalf("last error = %q", st.LastError)
	}
	if in := h.m.Inputs(); len(in) != 0 {
		t.Fatalf("a failed tunnel must route nothing: %+v", in)
	}
}

func TestViaDefaultPinsNothing(t *testing.T) {
	h := newHarness(t)
	spec := infraSpec()
	spec.Via = domain.TunnelViaDefault
	if _, err := h.m.Save(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
	if in := h.lastApply(); len(in) != 1 || len(in[0].Bypass) != 0 {
		t.Fatalf("via default must not pin the server: %+v", in)
	}
}

func TestHostnameRemoteIsResolvedAndPinned(t *testing.T) {
	h := newHarness(t)
	spec := infraSpec()
	spec.Config = strings.Replace(pushProfile, "remote 198.51.100.7 1194 tcp", "remote vpn.example.net 1194 tcp", 1)
	if _, err := h.m.Save(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, h.m, "infra", domain.TunnelConnected)
	if st.Server != "192.0.2.44:1194" {
		t.Fatalf("openvpn should dial the pinned address, got %q", st.Server)
	}
	if in := h.lastApply(); len(in[0].Bypass) != 1 || in[0].Bypass[0].String() != "192.0.2.44" {
		t.Fatalf("bypass = %+v", in)
	}
}

func TestSaveValidates(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	cases := map[string]func(*domain.TunnelSpec){
		"name":     func(s *domain.TunnelSpec) { s.Name = "Bad Name" },
		"password": func(s *domain.TunnelSpec) { s.Password = "" },
		"routes":   func(s *domain.TunnelSpec) { s.Routes = []string{"0.0.0.0/0"} },
		"config":   func(s *domain.TunnelSpec) { s.Config = "client\nremote 192.0.2.1\nup /bin/sh\n" },
		"via":      func(s *domain.TunnelSpec) { s.Via = "sideways" },
	}
	for field, mut := range cases {
		spec := infraSpec()
		mut(&spec)
		_, err := h.m.Save(ctx, spec)
		var ve *ValidationError
		if !errors.As(err, &ve) || ve.Issues[0].Field != field {
			t.Errorf("%s: got %v", field, err)
		}
	}
}

func TestUpdateKeepsSecretsAndReappliesRoutes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.m.Save(ctx, infraSpec()); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	first := waitState(t, h.m, "infra", domain.TunnelConnected)
	// An edit that only changes routes: no config, no password.
	st, err := h.m.Save(ctx, domain.TunnelSpec{Name: "infra", Routes: []string{"10.1.0.0/16"}})
	if err != nil {
		t.Fatal(err)
	}
	if !st.HasPassword || st.Username != "alice" || st.State != domain.TunnelConnected || !st.Since.Equal(*first.Since) {
		t.Fatalf("route-only edit must keep secrets and the connection: %+v", st)
	}
	if in := h.lastApply(); len(in) != 1 || strings.Join(in[0].Routes, ",") != "10.1.0.0/16" {
		t.Fatalf("new routes not applied: %+v", in)
	}
}

func TestSecretsStayOnDisk0600AndOffTheAPI(t *testing.T) {
	h := newHarness(t)
	st, err := h.m.Save(context.Background(), infraSpec())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(st)
	if strings.Contains(string(b), `"pw"`) || strings.Contains(string(b), "BEGIN CERTIFICATE") {
		t.Fatalf("status leaks secrets: %s", b)
	}
	fi, err := os.Stat(filepath.Join(h.dir, "infra.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("definition mode = %v, want 0600", fi.Mode().Perm())
	}
	di, _ := os.Stat(h.dir)
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", di.Mode().Perm())
	}
	// A new manager over the same dir sees the saved tunnel.
	m2, err := New(Options{Dir: h.dir, Launcher: &FakeLauncher{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := m2.Status("infra"); !ok || got.Username != "alice" || !got.HasPassword {
		t.Fatalf("reloaded = %+v", got)
	}
}

func TestConnectWithoutOpenVPNExplainsInstall(t *testing.T) {
	h := newHarness(t)
	h.m.o.Launcher = &FakeLauncher{Missing: true}
	if _, err := h.m.Save(context.Background(), infraSpec()); err != nil {
		t.Fatal(err)
	}
	err := h.m.Connect("infra")
	var ee *EngineError
	if !errors.Is(err, ErrEngineUnavailable) || !errors.As(err, &ee) || ee.Engine.Install == nil ||
		!strings.Contains(err.Error(), "isn't installed") {
		t.Fatalf("got %v", err)
	}
	if e := h.m.Engine(); e.Available || e.Install == nil || e.Install.System == "" {
		t.Fatalf("engine = %+v", e)
	}
	if st, _ := h.m.Status("infra"); st.State != domain.TunnelDisconnected {
		t.Fatalf("a refused connect must not leave a session: %+v", st)
	}
}

// Once shutdown has begun, nothing may start an openvpn: it would outlive
// the daemon with nothing to stop it.
func TestNoConnectOnceShuttingDown(t *testing.T) {
	h := newHarness(t)
	spec := infraSpec()
	spec.AutoConnect = true
	if _, err := h.m.Save(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	h.m.Shutdown()
	if err := h.m.Connect("infra"); !errors.Is(err, errShuttingDown) {
		t.Fatalf("connect after shutdown: %v", err)
	}
	h.m.StartAuto()
	if st, _ := h.m.Status("infra"); st.State != domain.TunnelDisconnected || st.LastError != "" {
		t.Fatalf("auto-connect after shutdown: %+v", st)
	}
}

func TestDeleteDisconnectsAndForgets(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.m.Save(ctx, infraSpec()); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
	if err := h.m.Delete(ctx, "infra"); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.m.Status("infra"); ok || len(h.m.List()) != 0 || len(h.m.Inputs()) != 0 {
		t.Fatal("tunnel still present after delete")
	}
	if _, err := os.Stat(filepath.Join(h.dir, "infra.json")); !os.IsNotExist(err) {
		t.Fatal("definition file not removed")
	}
}

// Delete racing Connect must never leave an openvpn session nothing tracks.
func TestDeleteRacingConnectLeavesNoOrphan(t *testing.T) {
	for i := 0; i < 20; i++ {
		h := newHarness(t)
		ctx := context.Background()
		if _, err := h.m.Save(ctx, infraSpec()); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { _ = h.m.Connect("infra"); close(done) }()
		_ = h.m.Delete(ctx, "infra")
		<-done
		// Whatever won, a session must either be tracked or not exist.
		h.m.mu.Lock()
		r := h.m.rt["infra"]
		h.m.mu.Unlock()
		if r == nil && len(h.m.Inputs()) != 0 {
			t.Fatal("inputs for a deleted tunnel")
		}
		h.m.Shutdown()
		if r != nil && r.sess != nil {
			t.Fatal("a session survived Shutdown")
		}
	}
}

func TestLogKeepsTheLastSessionsOutput(t *testing.T) {
	h := newHarness(t)
	spec := infraSpec()
	spec.Password = "wrong"
	if _, err := h.m.Save(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelFailed)
	lines, ok := h.m.Log("infra")
	if !ok || !strings.Contains(strings.Join(lines, "\n"), "AUTH_FAILED") {
		t.Fatalf("log = %v, %v", lines, ok)
	}
	if _, ok := h.m.Log("nope"); ok {
		t.Fatal("unknown tunnel must report !ok")
	}
}

func TestDiagnoseExplainsCommonFailures(t *testing.T) {
	eku := []string{"TLS: Initial packet from [AF_INET]x", "VERIFY KU OK", "Certificate does not have extended key usage extension", "VERIFY EKU ERROR"}
	if got := diagnose("infra", "tls-error", eku); !strings.Contains(got, "remote-cert-ku") {
		t.Errorf("EKU: %q", got)
	}
	hangup := []string{"old attempt VERIFY EKU ERROR", "TLS: Initial packet from [AF_INET]x", "VERIFY KU OK", "VERIFY OK: depth=0, CN=ca", "Connection reset, restarting [0]"}
	if got := diagnose("infra", "connection-reset", hangup); !strings.Contains(got, "--ask-password") {
		t.Errorf("hang-up after login: %q (only the latest attempt counts)", got)
	}
	ok := append(hangup[1:4:4], "Control Channel: TLSv1.2, cipher ECDHE-RSA-AES256-GCM-SHA384")
	if got := diagnose("infra", "connection-reset", ok); strings.Contains(got, "password") {
		t.Errorf("a completed handshake isn't a login failure: %q", got)
	}
}
