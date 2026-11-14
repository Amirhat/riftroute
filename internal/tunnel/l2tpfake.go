package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/Amirhat/riftroute/internal/ipsec"
	"github.com/Amirhat/riftroute/internal/l2tp"
)

// FakeIPsec stands in for charon under -provider fake and in tests: it
// records the connections brought up and down. A pre-shared key "wrong" is
// rejected, as a server would.
type FakeIPsec struct {
	// Fail, when set, is every Up's error.
	Fail error

	mu  sync.Mutex
	up  map[string]ipsec.Conn
	ups int
}

// Up implements IPsecRunner.
func (f *FakeIPsec) Up(ctx context.Context, c ipsec.Conn) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ups++
	if f.Fail != nil {
		return f.Fail
	}
	if c.PSK == "wrong" {
		return ipsec.LastingError("IPsec: the server rejected the shared secret (or its identity isn't the one expected)")
	}
	if f.up == nil {
		f.up = map[string]ipsec.Conn{}
	}
	f.up[c.Name] = c
	return nil
}

// Down implements IPsecRunner.
func (f *FakeIPsec) Down(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.up, name)
}

// Up reports the connections that are up now, and how many Ups there were.
func (f *FakeIPsec) Conns() (map[string]ipsec.Conn, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]ipsec.Conn{}
	for k, v := range f.up {
		out[k] = v
	}
	return out, f.ups
}

// FakeTUNs makes TUNs that carry nothing (tuntest), named utun2xx, each
// "configured" by OnUp and gone by OnDown (the fake provider's interface
// list).
type FakeTUNs struct {
	OnUp, OnDown func(iface, ip string)
	n            atomic.Int32
	mu           sync.Mutex
	addr         map[string]string
}

// CreateTUN implements WGSystem.
func (f *FakeTUNs) CreateTUN(int) (tun.Device, error) {
	name := fmt.Sprintf("utun%d", 200+f.n.Add(1))
	return &fakeTUN{Device: tuntest.NewChannelTUN().TUN(), name: name, f: f}, nil
}

// Configure implements WGSystem.
func (f *FakeTUNs) Configure(_ context.Context, iface string, addrs []netip.Addr, _ int) error {
	if len(addrs) == 0 {
		return nil
	}
	f.mu.Lock()
	if f.addr == nil {
		f.addr = map[string]string{}
	}
	f.addr[iface] = addrs[0].String()
	f.mu.Unlock()
	if f.OnUp != nil {
		f.OnUp(iface, addrs[0].String())
	}
	return nil
}

type fakeTUN struct {
	tun.Device
	name string
	f    *FakeTUNs
	once sync.Once
}

func (t *fakeTUN) Name() (string, error) { return t.name, nil }

func (t *fakeTUN) Close() error {
	t.once.Do(func() {
		t.f.mu.Lock()
		ip := t.f.addr[t.name]
		delete(t.f.addr, t.name)
		t.f.mu.Unlock()
		if t.f.OnDown != nil && ip != "" {
			t.f.OnDown(t.name, ip)
		}
	})
	return t.Device.Close()
}

// FakeL2TP is L2TP/IPsec's environment under -provider fake: FakeIPsec,
// FakeTUNs, and an in-process L2TP server for each attempt, whatever its
// server's address, which takes any password but "wrong".
func FakeL2TP(onUp, onDown func(iface, ip string)) *L2TPEnv {
	return &L2TPEnv{
		IPsec:  &FakeIPsec{},
		System: &FakeTUNs{OnUp: onUp, OnDown: onDown},
		Dial:   dialFakeServer,
	}
}

// dialFakeServer starts a FakeServer and connects to it; closing the
// connection stops it.
func dialFakeServer(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	srv := &l2tp.FakeServer{Auth: "pap", AnyPassword: true, DNS: []netip.Addr{netip.MustParseAddr("10.77.0.53")}}
	ap, err := srv.Start()
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", ap.String())
	if err != nil {
		srv.Close()
		return nil, err
	}
	return &serverConn{Conn: c, srv: srv}, nil
}

type serverConn struct {
	net.Conn
	srv *l2tp.FakeServer
}

func (c *serverConn) Close() error {
	c.srv.Close()
	return c.Conn.Close()
}
