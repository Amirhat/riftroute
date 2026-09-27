package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/Amirhat/riftroute/internal/domain"
)

type wgKeys struct{ priv, pub [32]byte }

func newWGKeys(t *testing.T) wgKeys {
	t.Helper()
	var k wgKeys
	if _, err := rand.Read(k.priv[:]); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(k.priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(k.pub[:], pub)
	return k
}

func (k wgKeys) b64(priv bool) string {
	if priv {
		return base64.StdEncoding.EncodeToString(k.priv[:])
	}
	return base64.StdEncoding.EncodeToString(k.pub[:])
}

// wgServer is a WireGuard peer in the test process: the other end of the
// tunnel, on loopback UDP.
type wgServer struct {
	tun  *tuntest.ChannelTUN
	dev  *device.Device
	port int
}

func startWGServer(t *testing.T, server, client wgKeys, port int) *wgServer {
	t.Helper()
	s := &wgServer{tun: tuntest.NewChannelTUN()}
	s.dev = device.NewDevice(s.tun.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	cfg := "private_key=" + hex.EncodeToString(server.priv[:]) + "\nlisten_port=" + strconv.Itoa(port) + "\n" +
		"public_key=" + hex.EncodeToString(client.pub[:]) + "\nallowed_ip=10.64.0.2/32\n"
	if err := s.dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.dev.Up(); err != nil {
		t.Fatal(err)
	}
	got, _ := s.dev.IpcGet()
	for _, l := range strings.Split(got, "\n") {
		if v, ok := strings.CutPrefix(l, "listen_port="); ok {
			s.port, _ = strconv.Atoi(v)
		}
	}
	if s.port == 0 {
		t.Fatal("the test server has no port")
	}
	t.Cleanup(s.dev.Close)
	return s
}

// fakeWG is the tun seam: an in-memory tun, and the addresses the driver
// asked for.
type fakeWG struct {
	mu    sync.Mutex
	tuns  []*tuntest.ChannelTUN
	addrs []netip.Addr
	fail  error
}

func (f *fakeWG) CreateTUN(mtu int) (tun.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := tuntest.NewChannelTUN()
	f.tuns = append(f.tuns, c)
	return c.TUN(), nil
}

func (f *fakeWG) Configure(_ context.Context, _ string, addrs []netip.Addr, _ int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addrs = append([]netip.Addr(nil), addrs...)
	return f.fail
}

func (f *fakeWG) configured() []netip.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addrs
}

func (f *fakeWG) tun(i int) *tuntest.ChannelTUN {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tuns[i]
}

// fastWG shortens WireGuard's timing for a test.
func fastWG(t *testing.T) {
	t.Helper()
	old := []time.Duration{wgPoll, wgFirstHandshake, wgRekeyAfter, wgNudgeEvery, wgStaleAfter, wgReresolveEvery}
	wgPoll, wgFirstHandshake, wgRekeyAfter, wgNudgeEvery, wgStaleAfter, wgReresolveEvery =
		20*time.Millisecond, 3*time.Second, 300*time.Millisecond, 100*time.Millisecond, time.Second, time.Hour
	t.Cleanup(func() {
		wgPoll, wgFirstHandshake, wgRekeyAfter, wgNudgeEvery, wgStaleAfter, wgReresolveEvery =
			old[0], old[1], old[2], old[3], old[4], old[5]
	})
}

func newWGManager(t *testing.T, sys *fakeWG) *Manager {
	t.Helper()
	m, err := New(Options{
		Dir: t.TempDir(), Launcher: &FakeLauncher{}, WireGuard: sys,
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Shutdown)
	return m
}

func wgSpec(client, server wgKeys, port int) domain.TunnelSpec {
	return domain.TunnelSpec{
		Name: "wg1", Type: domain.TunnelWireGuard, Via: domain.TunnelViaDefault, Routes: []string{"10.70.0.0/16"},
		Config: "[Interface]\nPrivateKey = " + client.b64(true) + "\nAddress = 10.64.0.2/24\nDNS = 10.64.0.1\n" +
			"[Peer]\nPublicKey = " + server.b64(false) + "\nEndpoint = server.test:" + strconv.Itoa(port) + "\nAllowedIPs = 10.64.0.0/24, 0.0.0.0/0\n",
	}
}

func waitWG(t *testing.T, m *Manager, what string, ok func(domain.TunnelStatus) bool) domain.TunnelStatus {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		st, _ := m.Status("wg1")
		if ok(st) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("waiting for %s: %+v", what, st)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The whole session: a handshake connects it, the tunnel's routes follow,
// traffic flows and is counted, and a disconnect closes the device.
func TestWireGuardSession(t *testing.T) {
	fastWG(t)
	client, server := newWGKeys(t), newWGKeys(t)
	srv := startWGServer(t, server, client, 0)
	sys := &fakeWG{}
	m := newWGManager(t, sys)
	if _, err := m.Save(context.Background(), wgSpec(client, server, srv.port)); err != nil {
		t.Fatal(err)
	}
	if st, _ := m.Status("wg1"); st.Type != domain.TunnelWireGuard || st.NeedsAuth || strings.Join(st.Ignored, ",") != "DNS" ||
		len(st.Servers) != 1 || st.Servers[0] != "server.test:"+strconv.Itoa(srv.port)+"/udp" {
		t.Fatalf("saved = %+v", st)
	}
	if err := m.Connect("wg1"); err != nil {
		t.Fatal(err)
	}
	st := waitWG(t, m, "connected", func(s domain.TunnelStatus) bool { return s.State == domain.TunnelConnected })
	if st.LocalIP != "10.64.0.2" || st.Server != "127.0.0.1:"+strconv.Itoa(srv.port) || st.Iface == "" || st.Since == nil {
		t.Errorf("connected = %+v", st)
	}
	if got := sys.configured(); len(got) != 1 || got[0] != netip.MustParseAddr("10.64.0.2") {
		t.Errorf("configured addresses = %v", got)
	}
	in := m.Inputs()
	if len(in) != 1 || in[0].Iface != st.Iface || len(in[0].Routes) != 1 || in[0].Routes[0] != "10.70.0.0/16" {
		t.Errorf("inputs = %+v", in)
	}
	for _, r := range in[0].Routes { // AllowedIPs are never routes
		if r == "0.0.0.0/0" || r == "10.64.0.0/24" {
			t.Errorf("an AllowedIPs entry became a route: %v", in[0].Routes)
		}
	}

	// A packet into the tunnel comes out at the server.
	sys.tun(0).Outbound <- tuntest.Ping(netip.MustParseAddr("10.64.0.1"), netip.MustParseAddr("10.64.0.2"))
	select {
	case <-srv.tun.Inbound:
	case <-time.After(5 * time.Second):
		t.Fatal("the packet never reached the server")
	}
	waitWG(t, m, "bytes counted", func(s domain.TunnelStatus) bool { return s.BytesOut > 0 && s.BytesIn > 0 })

	if err := m.Disconnect(context.Background(), "wg1"); err != nil {
		t.Fatal(err)
	}
	if st, _ := m.Status("wg1"); st.State != domain.TunnelDisconnected || st.LastError != "" || st.Iface != "" {
		t.Errorf("after the disconnect = %+v", st)
	}
	if len(m.Inputs()) != 0 {
		t.Errorf("inputs after the disconnect = %+v", m.Inputs())
	}
}

// A server that stops answering makes the tunnel reconnecting — its routes
// stay — and one that comes back connects it again, without a restart.
func TestWireGuardStaleHandshakeReconnects(t *testing.T) {
	fastWG(t)
	client, server := newWGKeys(t), newWGKeys(t)
	srv := startWGServer(t, server, client, 0)
	sys := &fakeWG{}
	m := newWGManager(t, sys)
	if _, err := m.Save(context.Background(), wgSpec(client, server, srv.port)); err != nil {
		t.Fatal(err)
	}
	if err := m.Connect("wg1"); err != nil {
		t.Fatal(err)
	}
	first := waitWG(t, m, "connected", func(s domain.TunnelStatus) bool { return s.State == domain.TunnelConnected })

	srv.dev.Close()
	st := waitWG(t, m, "reconnecting", func(s domain.TunnelStatus) bool { return s.State == domain.TunnelReconnecting })
	if st.Detail != "waiting for a handshake" {
		t.Errorf("reconnecting detail = %q", st.Detail)
	}
	if in := m.Inputs(); len(in) != 1 || in[0].Iface == "" {
		t.Errorf("a reconnecting tunnel's routes went: %+v", in)
	}

	startWGServer(t, server, client, srv.port)
	again := waitWG(t, m, "connected again", func(s domain.TunnelStatus) bool { return s.State == domain.TunnelConnected })
	if !again.Since.After(*first.Since) {
		t.Errorf("since = %v, want after %v", again.Since, first.Since)
	}
}

// A server that doesn't know the key never shakes hands: the tunnel fails
// with why, and nothing of the configuration's keys shows anywhere.
func TestWireGuardNoHandshakeFails(t *testing.T) {
	fastWG(t)
	client, server, stranger := newWGKeys(t), newWGKeys(t), newWGKeys(t)
	srv := startWGServer(t, server, stranger, 0)
	m := newWGManager(t, &fakeWG{})
	if _, err := m.Save(context.Background(), wgSpec(client, server, srv.port)); err != nil {
		t.Fatal(err)
	}
	if err := m.Connect("wg1"); err != nil {
		t.Fatal(err)
	}
	st := waitWG(t, m, "failed", func(s domain.TunnelStatus) bool { return s.State == domain.TunnelFailed })
	if !strings.Contains(st.LastError, "no handshake with the server") || strings.Contains(st.LastError, "--via default") {
		t.Errorf("last error = %q", st.LastError)
	}
	lines, _ := m.Log("wg1")
	all := st.LastError + strings.Join(lines, "\n")
	for _, secret := range []string{client.b64(true), hex.EncodeToString(client.priv[:])} {
		if strings.Contains(all, secret) {
			t.Fatal("the private key shows in the status or the log")
		}
	}
	if len(m.Inputs()) != 0 {
		t.Errorf("a failed tunnel still routes: %+v", m.Inputs())
	}
}

// Setting up the interface can fail (no root, a missing ip(8)): the tunnel
// fails with why, and the device is closed.
func TestWireGuardSetupFailure(t *testing.T) {
	fastWG(t)
	client, server := newWGKeys(t), newWGKeys(t)
	sys := &fakeWG{fail: io.ErrUnexpectedEOF}
	m := newWGManager(t, sys)
	if _, err := m.Save(context.Background(), wgSpec(client, server, 51820)); err != nil {
		t.Fatal(err)
	}
	if err := m.Connect("wg1"); err != nil {
		t.Fatal(err)
	}
	st := waitWG(t, m, "failed", func(s domain.TunnelStatus) bool { return s.State == domain.TunnelFailed })
	if !strings.Contains(st.LastError, "couldn't set up") {
		t.Errorf("last error = %q", st.LastError)
	}
	closed := make(chan struct{})
	go func() {
		for range sys.tun(0).TUN().Events() { // closed with the device
		}
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Error("the tun device wasn't closed")
	}
}

func TestWireGuardSaveRefusesCredentialsAndBadConfigs(t *testing.T) {
	client, server := newWGKeys(t), newWGKeys(t)
	m := newWGManager(t, &fakeWG{})
	spec := wgSpec(client, server, 51820)
	spec.Username, spec.Password = "alice", "secret"
	if _, err := m.Save(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "no username or password") {
		t.Errorf("credentials: %v", err)
	}
	spec = wgSpec(client, server, 51820)
	spec.Config = "client\nremote vpn.example.com 1194\n"
	if _, err := m.Save(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "config") {
		t.Errorf("an OpenVPN profile as WireGuard: %v", err)
	}
	spec.Config = ""
	if _, err := m.Save(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "WireGuard configuration (.conf) is required") {
		t.Errorf("no config: %v", err)
	}
}

// Endpoints resolve to one address each, v4 first; via direct pins exactly
// those and never a loopback, via default pins nothing.
func TestResolveEndpoints(t *testing.T) {
	m := &Manager{o: Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
			switch host {
			case "dual.test":
				return []netip.Addr{netip.MustParseAddr("2001:db8::9"), netip.MustParseAddr("203.0.113.9")}, nil
			case "local.test":
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
			return nil, io.EOF
		}}}
	peers := []WGPeer{{Endpoint: Remote{Host: "dual.test", Port: 51820}}, {Endpoint: Remote{Host: "198.51.100.7", Port: 4500}}}
	eps, pins, servers, err := m.resolveEndpoints(context.Background(), domain.TunnelViaDirect, peers)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 2 || eps[0].String() != "203.0.113.9:51820" || eps[1].String() != "198.51.100.7:4500" {
		t.Errorf("endpoints = %v", eps)
	}
	if len(pins) != 2 || len(servers) != 2 {
		t.Errorf("pins %v servers %v", pins, servers)
	}
	if _, pins, _, _ := m.resolveEndpoints(context.Background(), domain.TunnelViaDefault, peers); len(pins) != 0 {
		t.Errorf("via default pinned %v", pins)
	}
	if _, _, _, err := m.resolveEndpoints(context.Background(), domain.TunnelViaDirect, []WGPeer{{Endpoint: Remote{Host: "local.test", Port: 1}}}); err == nil {
		t.Error("a loopback endpoint was pinned")
	}
	if _, _, _, err := m.resolveEndpoints(context.Background(), domain.TunnelViaDirect, []WGPeer{{Endpoint: Remote{Host: "gone.test", Port: 1}}}); err == nil {
		t.Error("an unresolved endpoint connected")
	}
}
