package tunnel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/l2tp"
)

// l2tpHarness is a manager whose L2TP tunnels reach srv (whatever their
// server), with FakeIPsec and FakeTUNs on the harness's interface list.
type l2tpHarness struct {
	*harness
	ipsec *FakeIPsec
	srv   *l2tp.FakeServer
	dials int
	mu    sync.Mutex
}

func newL2TPHarness(t *testing.T, srv *l2tp.FakeServer) *l2tpHarness {
	t.Helper()
	fastIKE(t) // the attempts' backoff and the rejection waits
	h := &l2tpHarness{harness: newHarness(t), ipsec: &FakeIPsec{}, srv: srv}
	ap, err := srv.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	tuns := &FakeTUNs{
		OnUp: func(iface, ip string) {
			h.harness.mu.Lock()
			defer h.harness.mu.Unlock()
			h.ifaces = append(h.ifaces, domain.Iface{Name: iface, Up: true, Addrs: []string{ip + "/32"}, IsVPN: true})
		},
		OnDown: func(iface, _ string) {
			h.harness.mu.Lock()
			defer h.harness.mu.Unlock()
			h.ifaces = slices.DeleteFunc(h.ifaces, func(i domain.Iface) bool { return i.Name == iface })
		},
	}
	h.m.o.L2TP = &L2TPEnv{IPsec: h.ipsec, System: tuns,
		Dial: func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
			h.mu.Lock()
			h.dials++
			h.mu.Unlock()
			var d net.Dialer
			return d.DialContext(ctx, "udp", ap.String())
		}}
	return h
}

func l2tpSpec(name, psk string) domain.TunnelSpec {
	cfg := "[L2TP]\nServer = 203.0.113.9\n"
	if psk == "" {
		cfg += "IPsec = none\n"
	} else {
		cfg += "PreSharedKey = " + psk + "\n"
	}
	return domain.TunnelSpec{Name: name, Type: domain.TunnelL2TP, Config: cfg, Username: "alice", Password: "s3cret",
		Routes: []string{"10.40.0.0/16"}}
}

// A PSK tunnel: IPsec first, then L2TP and PPP; connected on its TUN with
// PPP's address; a Disconnect takes it all down.
func TestL2TPConnects(t *testing.T) {
	h := newL2TPHarness(t, &l2tp.FakeServer{Users: map[string]string{"alice": "s3cret"}})
	if _, err := h.m.Save(t.Context(), l2tpSpec("office", "psk-secret")); err != nil {
		t.Fatal(err)
	}
	st, _ := h.m.Status("office")
	if !st.NeedsAuth || !st.HasPassword || len(st.Servers) != 1 || !strings.Contains(st.Servers[0], "203.0.113.9 (L2TP/IPsec)") {
		t.Fatalf("saved: %+v", st)
	}
	if err := h.m.Connect("office"); err != nil {
		t.Fatal(err)
	}
	st = waitState(t, h.m, "office", domain.TunnelConnected)
	if !strings.HasPrefix(st.Iface, "utun2") {
		t.Errorf("iface %q", st.Iface)
	}
	conns, _ := h.ipsec.Conns()
	c, ok := conns["rr-office"]
	if !ok || c.PSK != "psk-secret" || c.Server.String() != "203.0.113.9" || c.Version != 1 {
		t.Fatalf("IPsec: %+v", conns)
	}
	if err := h.m.Disconnect(t.Context(), "office"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "IPsec down", func() bool { c, _ := h.ipsec.Conns(); return len(c) == 0 })
	h.harness.mu.Lock()
	n := len(h.ifaces)
	h.harness.mu.Unlock()
	if n != 0 {
		t.Errorf("the TUN stayed: %d interfaces", n)
	}
}

// A login that has never worked, rejected: failed at once, tried once (#37:
// no lockout).
func TestL2TPRejectedLoginIsNotRetried(t *testing.T) {
	h := newL2TPHarness(t, &l2tp.FakeServer{Users: map[string]string{"alice": "other"}})
	if _, err := h.m.Save(t.Context(), l2tpSpec("office", "k")); err != nil {
		t.Fatal(err)
	}
	_ = h.m.Connect("office")
	st := waitState(t, h.m, "office", domain.TunnelFailed)
	if !strings.Contains(st.LastError, "rejected the username or password") || h.srv.Logins() != 1 {
		t.Fatalf("%q after %d logins", st.LastError, h.srv.Logins())
	}
	if code := failureCode(st.LastError); code != "auth" {
		t.Errorf("failure code %q", code)
	}
}

// A wrong pre-shared key ends it at once too.
func TestL2TPWrongPSK(t *testing.T) {
	h := newL2TPHarness(t, &l2tp.FakeServer{Users: map[string]string{"alice": "s3cret"}})
	if _, err := h.m.Save(t.Context(), l2tpSpec("office", "wrong")); err != nil {
		t.Fatal(err)
	}
	_ = h.m.Connect("office")
	st := waitState(t, h.m, "office", domain.TunnelFailed)
	if _, ups := h.ipsec.Conns(); ups != 1 || !strings.Contains(st.LastError, "rejected the shared secret") {
		t.Fatalf("%q after %d tries", st.LastError, ups)
	}
	if h.dials != 0 {
		t.Error("L2TP was sent without IPsec")
	}
}

// An IPsec that doesn't answer is tried again (it may be a moment's).
func TestL2TPIPsecUnansweredIsRetried(t *testing.T) {
	h := newL2TPHarness(t, &l2tp.FakeServer{Users: map[string]string{"alice": "s3cret"}})
	h.ipsec.Fail = errors.New("IPsec: the server didn't answer (IKE on UDP 500/4500)")
	if _, err := h.m.Save(t.Context(), l2tpSpec("office", "k")); err != nil {
		t.Fatal(err)
	}
	_ = h.m.Connect("office")
	st := waitState(t, h.m, "office", domain.TunnelFailed)
	if _, ups := h.ipsec.Conns(); ups != maxFailedAttempts || !strings.Contains(st.LastError, "gave up after") {
		t.Fatalf("%q after %d tries", st.LastError, ups)
	}
}

// Without IPsec, a server that takes only PAP is refused: the password
// isn't sent in the clear.
func TestL2TPNoIPsecRefusesPAP(t *testing.T) {
	h := newL2TPHarness(t, &l2tp.FakeServer{Users: map[string]string{"alice": "s3cret"}, Auth: "pap", Insist: true})
	if _, err := h.m.Save(t.Context(), l2tpSpec("office", "")); err != nil {
		t.Fatal(err)
	}
	st, _ := h.m.Status("office")
	if !strings.Contains(st.Servers[0], "unencrypted") {
		t.Errorf("servers %v", st.Servers)
	}
	_ = h.m.Connect("office")
	st = waitState(t, h.m, "office", domain.TunnelFailed)
	if !strings.Contains(st.LastError, "sends the password unencrypted") || h.srv.Logins() != 0 {
		t.Fatalf("%q", st.LastError)
	}
	if _, ups := h.ipsec.Conns(); ups != 0 {
		t.Error("IPsec for a tunnel without it")
	}
}

// A full tunnel takes the DNS servers IPCP gives.
func TestL2TPFullTunnelDNS(t *testing.T) {
	h := newL2TPHarness(t, &l2tp.FakeServer{Users: map[string]string{"alice": "s3cret"},
		DNS: []netip.Addr{netip.MustParseAddr("10.77.0.53")}})
	spec := l2tpSpec("office", "k")
	on := true
	spec.AllTraffic = &on
	if _, err := h.m.Save(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	_ = h.m.Connect("office")
	waitState(t, h.m, "office", domain.TunnelConnected)
	h.m.mu.Lock()
	dns := h.m.rt["office"].dns.Servers
	h.m.mu.Unlock()
	if len(dns) != 1 || dns[0].String() != "10.77.0.53" {
		t.Fatalf("dns %v", dns)
	}
}

// The server going away: reconnecting, then connected again.
func TestL2TPServerHangsUp(t *testing.T) {
	h := newL2TPHarness(t, &l2tp.FakeServer{Users: map[string]string{"alice": "s3cret"}})
	if _, err := h.m.Save(t.Context(), l2tpSpec("office", "k")); err != nil {
		t.Fatal(err)
	}
	_ = h.m.Connect("office")
	waitState(t, h.m, "office", domain.TunnelConnected)
	h.srv.HangUp()
	waitFor(t, "a second connection", func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.dials >= 2
	})
	waitState(t, h.m, "office", domain.TunnelConnected)
}

// Its configuration: the [L2TP] file's checks.
func TestParseL2TP(t *testing.T) {
	for cfg, want := range map[string]string{
		"[L2TP]\nServer = vpn.example.com\nPreSharedKey = k\n":                "",
		"[L2TP]\nServer = vpn.example.com\nIPsec = none\n":                    "",
		"[L2TP]\nServer = vpn.example.com\n":                                  "no IPsec login",
		"[L2TP]\nPreSharedKey = k\n":                                          "no server",
		"[L2TP]\nServer = vpn.example.com\nIPsec = none\nPreSharedKey = k\n":  "which one",
		"[L2TP]\nServer = vpn.example.com\nPreSharedKey = k\nIKEVersion = 3\n": "IKEVersion",
		"[L2TP]\nServer = vpn.example.com\nPreSharedKey = k\nColor = red\n":    "unknown setting",
		"Server = x\n[L2TP]\n":                                                "before [L2TP]",
		"[Interface]\n":                                                       "no [L2TP] section",
	} {
		_, err := ParseL2TP(cfg)
		if (want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), want)) {
			t.Errorf("%q: %v", cfg, err)
		}
	}
	c, err := ParseL2TP("[L2TP]\n# a comment\nServer = 192.0.2.7\nSharedSecret = k\nIKEVersion = 2\nUsername = bob\n")
	if err != nil || c.IPsec != L2TPPSK || c.PSK != "k" || c.IKEVersion != 2 || c.Username != "bob" || c.Remote.Port != 1701 {
		t.Fatalf("%+v %v", c, err)
	}
}

// The engine says what's missing for IPsec.
func TestL2TPEngineWithoutIPsec(t *testing.T) {
	h := newHarness(t)
	h.m.o.L2TP = &L2TPEnv{System: &FakeTUNs{}}
	e := h.m.Engine()
	if e.L2TP == nil || !e.L2TP.Available || !strings.Contains(e.L2TP.Problem, "only L2TP without IPsec") {
		t.Fatalf("%+v", e.L2TP)
	}
	if _, err := h.m.Save(t.Context(), l2tpSpec("office", "k")); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("office"); err == nil || !strings.Contains(err.Error(), "IPsec for L2TP tunnels isn't available") {
		t.Fatalf("%v", err)
	}
}
