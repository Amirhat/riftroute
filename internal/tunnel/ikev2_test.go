package tunnel

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/strongswan/govici/vici"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/Amirhat/riftroute/internal/domain"
)

// fastIKE shortens the IKEv2 session's timers for a test.
func fastIKE(t *testing.T) {
	t.Helper()
	poll, start, conn, down, stop, bmin, bmax := ikePoll, ikeStartWait, ikeConnectWait, ikeDownAfter, ikeStopWait, ikeBackoffMin, ikeBackoffMax
	ikePoll, ikeStartWait, ikeConnectWait, ikeDownAfter, ikeStopWait = 5*time.Millisecond, time.Second, 2*time.Second, 30*time.Millisecond, time.Second
	ikeBackoffMin, ikeBackoffMax = time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() {
		ikePoll, ikeStartWait, ikeConnectWait, ikeDownAfter, ikeStopWait, ikeBackoffMin, ikeBackoffMax = poll, start, conn, down, stop, bmin, bmax
	})
}

// newIKEHarness is newHarness with a FakeIKE whose interface joins the
// harness's list while it's up.
func newIKEHarness(t *testing.T) (*harness, *FakeIKE) {
	t.Helper()
	fastIKE(t)
	h := newHarness(t)
	fi := &FakeIKE{
		OnUp: func(iface, ip string) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.ifaces = append(h.ifaces, domain.Iface{Name: iface, Up: true, Addrs: []string{ip + "/32"}, IsVPN: true})
		},
		OnDown: func(iface, _ string) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.ifaces = slices.DeleteFunc(h.ifaces, func(i domain.Iface) bool { return i.Name == iface })
		},
	}
	h.m.o.IKE = fi
	return h, fi
}

func ikeSpec(t *testing.T, pki testPKI) domain.TunnelSpec {
	t.Helper()
	raw := profile("IKEv2", certIKEv2,
		dataPayload(payloadPKCS12, "P12-UUID", pki.p12(t, pkcs12.LegacyRC2, "pw"), `<key>Password</key><string>pw</string>`),
		dataPayload(payloadRoot, "CA-UUID", pki.caDER, ""))
	return domain.TunnelSpec{Name: "office", Type: domain.TunnelIKEv2, Config: raw, Routes: []string{"10.30.0.0/16"}}
}

// argAfter is the value that follows flag in args.
func argAfter(args []string, flag string) string {
	if i := slices.Index(args, flag); i >= 0 && i+1 < len(args) {
		return args[i+1]
	}
	return ""
}

// A certificate profile connects: charon-cmd gets the pinned server, the
// profile's identities and its own key, CA and config (0600, gone after);
// the tunnel's networks go into the interface holding the address the
// server assigned; a disconnect stops it and withdraws them.
func TestIKEv2Session(t *testing.T) {
	h, fi := newIKEHarness(t)
	ctx := t.Context()
	pki := newTestPKI(t)
	if _, err := h.m.Save(ctx, ikeSpec(t, pki)); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("office"); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, h.m, "office", domain.TunnelConnected)
	if st.Iface != "utun8" || st.LocalIP != "10.98.0.2" || st.Server != "192.0.2.44:4500" || st.Since == nil || st.BytesIn != 100 {
		t.Fatalf("connected status = %+v", st)
	}
	in := h.lastApply()
	if len(in) != 1 || in[0].Iface != "utun8" || strings.Join(in[0].Routes, ",") != "10.30.0.0/16" ||
		len(in[0].Bypass) != 1 || in[0].Bypass[0].String() != "192.0.2.44" {
		t.Fatalf("apply inputs = %+v", in)
	}

	started := fi.Started()
	if len(started) != 1 {
		t.Fatalf("started %d sessions", len(started))
	}
	args := started[0].Args
	for flag, want := range map[string]string{
		"--host": "192.0.2.44", "--identity": "alice@example.com", "--remote-identity": "vpn.example.com",
		"--profile": "ikev2-pub", "--ike-proposal": "aes256gcm16-prfsha256-ecp384", "--esp-proposal": "aes256gcm16-ecp384",
	} {
		if got := argAfter(args, flag); got != want {
			t.Errorf("%s = %q, want %q (args %q)", flag, got, want, args)
		}
	}
	key := argAfter(args, "--priv")
	fi2, err := os.Stat(key)
	if err != nil || fi2.Mode().Perm() != 0o600 || filepath.Dir(key) != h.m.runDir {
		t.Fatalf("key file %s: %v %v", key, fi2, err)
	}
	if data, _ := os.ReadFile(started[0].Conf); !bytes.Contains(data, []byte("install_routes = no")) {
		t.Errorf("config:\n%s", data)
	}

	if err := h.m.Disconnect(ctx, "office"); err != nil {
		t.Fatal(err)
	}
	st = waitState(t, h.m, "office", domain.TunnelDisconnected)
	if st.LastError != "" || st.Iface != "" || fi.Running() != 0 {
		t.Fatalf("after disconnect: %+v (running %d)", st, fi.Running())
	}
	if in := h.lastApply(); len(in) != 0 {
		t.Fatalf("routes must be withdrawn on disconnect, last apply = %+v", in)
	}
	ents, _ := os.ReadDir(h.m.runDir)
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			t.Errorf("runtime file left behind: %s", e.Name())
		}
	}
}

// charon-cmd stays up when an established connection drops: the session
// notices, restarts it, and is connected again.
func TestIKEv2ReconnectsAfterADrop(t *testing.T) {
	h, fi := newIKEHarness(t)
	if _, err := h.m.Save(t.Context(), ikeSpec(t, newTestPKI(t))); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("office"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "office", domain.TunnelConnected)
	fi.Drop()
	waitFor(t, "a second charon-cmd", func() bool { return len(fi.Started()) == 2 })
	st := waitState(t, h.m, "office", domain.TunnelConnected)
	if st.Iface != "utun8" || fi.Running() != 1 {
		t.Fatalf("after the drop: %+v (running %d)", st, fi.Running())
	}
}

// A connection that never comes up is retried, then given up, with the
// reason from charon's output.
func TestIKEv2GivesUpWithTheReason(t *testing.T) {
	h, fi := newIKEHarness(t)
	fi.Fail = []string{"received AUTHENTICATION_FAILED notify error"}
	if _, err := h.m.Save(t.Context(), ikeSpec(t, newTestPKI(t))); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("office"); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, h.m, "office", domain.TunnelFailed)
	if !strings.Contains(st.LastError, "gave up after 6 attempts") || !strings.Contains(st.LastError, "rejected this profile's certificate") {
		t.Fatalf("last error = %q", st.LastError)
	}
	if n := len(fi.Started()); n != maxFailedAttempts {
		t.Fatalf("%d attempts", n)
	}
}

// What can't run is refused with the reason: a login charon-cmd would ask
// for on a terminal, a server that assigns no address, no strongSwan.
func TestIKEv2Refusals(t *testing.T) {
	h, fi := newIKEHarness(t)
	ctx := t.Context()
	eap := domain.TunnelSpec{Name: "eap", Type: domain.TunnelIKEv2, Routes: []string{"10.30.0.0/16"}, Config: profile("IKEv2", `
        <key>RemoteAddress</key><string>203.0.113.9</string>
        <key>AuthenticationMethod</key><string>None</string>
        <key>ExtendedAuthEnabled</key><true/>
        <key>AuthName</key><string>alice</string>
        <key>AuthPassword</key><string>pw</string>`)}
	if _, err := h.m.Save(ctx, eap); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("eap"); err == nil || !strings.Contains(err.Error(), "log in with a certificate") {
		t.Fatalf("EAP connect = %v", err)
	}

	fi.VIP = "none"
	if _, err := h.m.Save(ctx, ikeSpec(t, newTestPKI(t))); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("office"); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, h.m, "office", domain.TunnelFailed)
	if !strings.Contains(st.LastError, "assigned no address") || len(fi.Started()) != 1 || fi.Running() != 0 {
		t.Fatalf("no address: %+v (started %d, running %d)", st, len(fi.Started()), fi.Running())
	}

	fi.Missing = true
	var ee *EngineError
	if err := h.m.Connect("office"); !errors.As(err, &ee) || !strings.Contains(err.Error(), "charon-cmd") {
		t.Fatalf("no strongSwan: %v", err)
	}
	h.m.o.IKE = nil
	if err := h.m.Connect("office"); !errors.As(err, &ee) {
		t.Fatalf("no IKE launcher: %v", err)
	}
}

// renderIKE: the files and arguments one charon-cmd session is started
// with.
func TestRenderIKE(t *testing.T) {
	pki := newTestPKI(t)
	c, err := ParseMobileconfig(ikeSpec(t, pki).Config)
	if err != nil {
		t.Fatal(err)
	}
	dir := "/run/rr"
	st, err := renderIKE(c, nil, "192.0.2.44", dir, "office", true, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"--debug", "1", "--host", "192.0.2.44", "--identity", "alice@example.com", "--remote-identity", "vpn.example.com",
		"--profile", "ikev2-pub", "--cert", dir + "/office.cert.pem", "--priv", dir + "/office.key.pem",
		"--cert", dir + "/office.ca0.pem",
		"--ike-proposal", "aes256gcm16-prfsha256-ecp384", "--esp-proposal", "aes256gcm16-ecp384",
		"--remote-ts", "0.0.0.0/0", "--remote-ts", "::/0",
	}
	if !slices.Equal(st.Args, want) {
		t.Errorf("args =\n%q\nwant\n%q", st.Args, want)
	}
	if st.Conf != dir+"/office.conf" || st.Socket != dir+"/office.vici" {
		t.Errorf("conf %s, socket %s", st.Conf, st.Socket)
	}
	files := map[string][]byte{}
	for _, f := range st.Files {
		files[filepath.Base(f.Name)] = f.Data
	}
	b, _ := pem.Decode(files["office.key.pem"])
	if b == nil || b.Type != "PRIVATE KEY" {
		t.Fatal("no PKCS#8 key")
	}
	if k, err := x509.ParsePKCS8PrivateKey(b.Bytes); err != nil || !pki.key.Equal(k) {
		t.Errorf("key doesn't round-trip: %v", err)
	}
	if b, _ := pem.Decode(files["office.ca0.pem"]); b == nil || !bytes.Equal(b.Bytes, pki.caDER) {
		t.Error("CA file isn't the profile's CA")
	}
	if b, _ := pem.Decode(files["office.cert.pem"]); b == nil || !bytes.Equal(b.Bytes, pki.client.Raw) {
		t.Error("cert file isn't the login certificate")
	}
	conf := string(files["office.conf"])
	for _, s := range []string{"install_routes = no", "socket = unix:///run/rr/office.vici", "kernel-libipsec!", "vici!", "port = 0"} {
		if !strings.Contains(conf, s) {
			t.Errorf("config lacks %q:\n%s", s, conf)
		}
	}
	for _, s := range []string{"resolve", "updown", "attr"} {
		if strings.Contains(conf, " "+s+" ") {
			t.Errorf("config loads %s:\n%s", s, conf)
		}
	}
	if darwin, linux := ikeConf("darwin", "/s", false), ikeConf("linux", "/s", false); strings.Contains(darwin, "routing_table") ||
		!strings.Contains(darwin, " kernel-pfroute ") || !strings.Contains(linux, "routing_table = 52520\n") ||
		!strings.Contains(linux, "routing_table_prio = 52520\n") || !strings.Contains(linux, " kernel-netlink ") ||
		!strings.Contains(linux, "stderr {") || strings.Contains(linux, "pem!") {
		t.Errorf("per-OS config:\n%s\n%s", darwin, linux)
	}

	// An older charon-cmd (strongSwan 5.x, as Debian and Ubuntu ship) takes
	// the login as a PKCS#12, whose password it reads from stdin.
	st, err = renderIKE(c, nil, "192.0.2.44", dir, "office", false, true)
	if err != nil {
		t.Fatal(err)
	}
	if argAfter(st.Args, "--p12") != dir+"/office.p12" || slices.Contains(st.Args, "--priv") ||
		argAfter(st.Args, "--cert") != dir+"/office.ca0.pem" {
		t.Errorf("p12 args: %q", st.Args)
	}
	for _, f := range st.Files {
		switch filepath.Base(f.Name) {
		case "office.p12":
			key, cert, _, err := pkcs12.DecodeChain(f.Data, strings.TrimSuffix(st.Stdin, "\n"))
			if err != nil || !pki.key.Equal(key) || !cert.Equal(pki.client) || len(st.Stdin) != 33 {
				t.Errorf("the PKCS#12 doesn't open, with the password on stdin, to the login: %v", err)
			}
		case "office.conf":
			if !strings.Contains(string(f.Data), " pkcs7 pkcs12") {
				t.Errorf("a p12 session must load pkcs12 and pkcs7:\n%s", f.Data)
			}
		case "office.key.pem", "office.cert.pem":
			t.Errorf("%s written beside the PKCS#12", f.Name)
		}
	}
	for v, want := range map[string]bool{"5.9.8": true, "5.9.13": true, "6.0.1": false, "6.1.0": false, "": false} {
		if ikeKeyAsP12(v) != want {
			t.Errorf("ikeKeyAsP12(%q) != %v", v, want)
		}
	}

	// v4 only: no IPv6 asked for.
	if st, _ := renderIKE(c, nil, "192.0.2.44", dir, "office", false, false); slices.Contains(st.Args, "::/0") {
		t.Errorf("v4-only args: %q", st.Args)
	}
	// No CA in the profile: the system's, or a refusal.
	c.CAs = nil
	if _, err := renderIKE(c, nil, "h", dir, "office", false, false); err == nil || !strings.Contains(err.Error(), "no certificate authority") {
		t.Errorf("no CA = %v", err)
	}
	st, err = renderIKE(c, []*x509.Certificate{pki.caCert, pki.caCert}, "h", dir, "office", false, false)
	if err != nil || argAfter(st.Args, "--cert") != dir+"/office.cert.pem" || !slices.Contains(st.Args, dir+"/office.ca1.pem") {
		t.Errorf("system roots: %v %q", err, st.Args)
	}
	c.Auth = IKEv2PSK
	if _, err := renderIKE(c, nil, "h", dir, "office", false, false); err == nil {
		t.Error("a PSK profile rendered")
	}
}

// list-sas as charon sends it: the SA that's up, its assigned addresses,
// where it's connected and its traffic.
func TestParseSAs(t *testing.T) {
	sa := func(state, child string, vips ...string) *vici.Message {
		c := vici.NewMessage()
		_ = c.Set("state", child)
		_ = c.Set("bytes-in", "1000")
		_ = c.Set("bytes-out", "200")
		children := vici.NewMessage()
		_ = children.Set("cmd-1", c)
		m := vici.NewMessage()
		_ = m.Set("state", state)
		_ = m.Set("remote-host", "192.0.2.44")
		_ = m.Set("remote-port", "4500")
		if vips != nil {
			_ = m.Set("local-vips", vips)
		}
		_ = m.Set("child-sas", children)
		out := vici.NewMessage()
		_ = out.Set("cmd", m)
		return out
	}
	st := parseSAs([]*vici.Message{sa("ESTABLISHED", "INSTALLED", "10.98.0.2", "fd00::2")})
	if !st.Up || st.State != "ESTABLISHED" || st.Server.String() != "192.0.2.44:4500" || st.In != 1000 || st.Out != 200 ||
		!slices.Equal(st.VIPs, []netip.Addr{netip.MustParseAddr("10.98.0.2"), netip.MustParseAddr("fd00::2")}) {
		t.Errorf("up = %+v", st)
	}
	if st := parseSAs([]*vici.Message{sa("CONNECTING", "CREATED")}); st.Up || st.State != "CONNECTING" {
		t.Errorf("connecting = %+v", st)
	}
	if st := parseSAs([]*vici.Message{sa("ESTABLISHED", "DELETING", "10.98.0.2")}); st.Up {
		t.Errorf("no child installed = %+v", st)
	}
	// Rekeying: the old SA's going, the new one's up.
	if st := parseSAs([]*vici.Message{sa("DELETING", "DELETING"), sa("ESTABLISHED", "INSTALLED", "10.98.0.3")}); !st.Up || st.VIPs[0].String() != "10.98.0.3" {
		t.Errorf("rekeyed = %+v", st)
	}
	if st := parseSAs(nil); st.Up || st.State != "" {
		t.Errorf("none = %+v", st)
	}
}

// ikeProcess.Status speaks VICI to charon's socket (here a stand-in that
// answers list-sas the way charon does).
func TestIKEStatusOverVICI(t *testing.T) {
	sock := filepath.Join(shortTempDir(t), "c.vici")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go serveVICI(l)

	p := &ikeProcess{execProcess: execProcess{done: make(chan struct{})}, socket: sock}
	t.Cleanup(p.closeVICI)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for range 2 { // the session is kept for the next
		st, err := p.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !st.Up || len(st.VIPs) != 1 || st.VIPs[0].String() != "10.98.0.2" || st.Server.String() != "192.0.2.44:4500" {
			t.Fatalf("status = %+v", st)
		}
	}
	close(p.done)
	if _, err := p.Status(ctx); !errors.Is(err, errIKENotRunning) {
		t.Fatalf("after exit: %v", err)
	}
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "rrv") // a unix socket path must be short
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// serveVICI answers list-sas with one established SA, per the VICI protocol:
// each packet a 32-bit length, a type, a name for the named ones, and a
// message of typed elements.
func serveVICI(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			for {
				var n uint32
				if binary.Read(c, binary.BigEndian, &n) != nil {
					return
				}
				pkt := make([]byte, n)
				if _, err := io.ReadFull(c, pkt); err != nil {
					return
				}
				switch pkt[0] {
				case 3, 4: // EVENT_REGISTER, EVENT_UNREGISTER
					writeVICI(c, []byte{5}) // EVENT_CONFIRM
				case 0: // CMD_REQUEST
					if name := string(pkt[2 : 2+pkt[1]]); name != "list-sas" {
						writeVICI(c, []byte{2}) // CMD_UNKNOWN
						continue
					}
					var m bytes.Buffer
					section := func(name string) { m.WriteByte(1); m.WriteByte(byte(len(name))); m.WriteString(name) }
					kv := func(k, v string) {
						m.WriteByte(3)
						m.WriteByte(byte(len(k)))
						m.WriteString(k)
						_ = binary.Write(&m, binary.BigEndian, uint16(len(v)))
						m.WriteString(v)
					}
					section("cmd")
					kv("state", "ESTABLISHED")
					kv("remote-host", "192.0.2.44")
					kv("remote-port", "4500")
					m.WriteByte(4)
					m.WriteByte(byte(len("local-vips")))
					m.WriteString("local-vips")
					m.WriteByte(5)
					_ = binary.Write(&m, binary.BigEndian, uint16(len("10.98.0.2")))
					m.WriteString("10.98.0.2")
					m.WriteByte(6)
					section("child-sas")
					section("cmd-1")
					kv("state", "INSTALLED")
					kv("bytes-in", "5")
					m.WriteByte(2)
					m.WriteByte(2)
					m.WriteByte(2)
					ev := append([]byte{7, byte(len("list-sa"))}, "list-sa"...)
					writeVICI(c, append(ev, m.Bytes()...))
					writeVICI(c, []byte{1}) // CMD_RESPONSE, empty
				}
			}
		}()
	}
}

func writeVICI(w io.Writer, pkt []byte) {
	_ = binary.Write(w, binary.BigEndian, uint32(len(pkt)))
	_, _ = w.Write(pkt)
}

// diagnoseIKE names the usual failures from charon's output.
func TestDiagnoseIKE(t *testing.T) {
	for _, tc := range []struct {
		line string
		via  domain.TunnelVia
		want string
	}{
		{"loading critical plugin 'kernel-libipsec' failed", domain.TunnelViaDirect, "couldn't load a part"},
		{"00[LIB] plugin 'openssl': failed to load - openssl_plugin_create not found, plugin may be shipped in a separate package",
			domain.TunnelViaDirect, "strongSwan's openssl plugin isn't installed"},
		{"00[LIB] plugin 'md4': failed to load - md4_plugin_create not found, plugin may be shipped in a separate package",
			domain.TunnelViaDirect, "couldn't connect: 00[LIB] plugin 'md4'"}, // not one a session needs
		{"00[LIB] feature CUSTOM:kernel-ipsec in plugin 'kernel-netlink' failed to load", domain.TunnelViaDirect,
			"couldn't connect: 00[LIB] feature"}, // a feature, not the plugin
		{"received NO_PROPOSAL_CHOSEN notify error", domain.TunnelViaDirect, "encryption settings"},
		{"constraint check failed: identity 'vpn.example.com' required", domain.TunnelViaDirect, "RemoteIdentifier"},
		{"no trusted ECDSA public key found for 'vpn.example.com'", domain.TunnelViaDirect, "certificate authorities"},
		{"giving up after 5 retransmits", domain.TunnelViaDirect, "Windscribe"},
		{"giving up after 5 retransmits", domain.TunnelViaDefault, "UDP ports 500 and 4500"},
		{"something else", domain.TunnelViaDirect, "couldn't connect: something else"},
	} {
		got := diagnoseIKE("office", tc.via, []string{"Starting charon-cmd IKE client", tc.line})
		if !strings.Contains(got, tc.want) {
			t.Errorf("%q → %q, want %q", tc.line, got, tc.want)
		}
	}
	if got := diagnoseIKE("office", domain.TunnelViaDefault, []string{"giving up after 5 retransmits"}); strings.Contains(got, "Windscribe") {
		t.Errorf("via default: %q", got)
	}
}

// Whether charon-cmd can run here, and how to fix it when not: RiftRoute's
// own on macOS, the distribution's packages on Linux, 5.9 or newer.
func TestDetectIKEEngine(t *testing.T) {
	missing := func() (string, fs.FileInfo, error) { return "", nil, errNotFound }
	found := func() (string, fs.FileInfo, error) { return "/usr/sbin/charon-cmd", nil, nil }
	ver := func(v string) func(string, fs.FileInfo) (string, error) {
		return func(string, fs.FileInfo) (string, error) { return v, nil }
	}
	mac := hostInfo{goos: "darwin"}
	if e := detectIKEEngine(mac, missing, nil); e.Available || e.Install == nil ||
		e.Install.Action != domain.TunnelInstallUpdate || !strings.Contains(e.Install.Note, "riftroute update check") {
		t.Errorf("macOS, missing: %+v %+v", e, e.Install)
	}
	ubuntu := hostInfo{goos: "linux", osRelease: map[string]string{"ID": "pop", "ID_LIKE": "ubuntu debian"}}
	if e := detectIKEEngine(ubuntu, missing, nil); e.Install == nil ||
		!slices.Equal(e.Install.Commands, []string{"sudo apt install --no-install-recommends charon-cmd libcharon-extra-plugins libstrongswan-standard-plugins strongswan-swanctl"}) {
		t.Errorf("Ubuntu-like, missing: %+v", e.Install)
	}
	if e := detectIKEEngine(hostInfo{goos: "linux", osRelease: map[string]string{"ID": "nixos"}}, missing, nil); e.Install == nil ||
		e.Install.Note != ikeLinuxNote {
		t.Errorf("unknown Linux: %+v", e.Install)
	}
	if e := detectIKEEngine(ubuntu, found, ver("5.8.2")); e.Available || !strings.Contains(e.Problem, "too old") ||
		!slices.Equal(e.Install.Commands, []string{"sudo apt install --reinstall --no-install-recommends charon-cmd libcharon-extra-plugins libstrongswan-standard-plugins strongswan-swanctl"}) {
		t.Errorf("too old: %+v", e)
	}
	if e := detectIKEEngine(ubuntu, found, ver("6.1.0")); !e.Available || e.Version != "6.1.0" || e.Path != "/usr/sbin/charon-cmd" {
		t.Errorf("fine: %+v", e)
	}
	if e := detectIKEEngine(hostInfo{goos: "windows"}, found, ver("6.1.0")); e.Available {
		t.Errorf("windows: %+v", e)
	}
	if !ikeTooOld("5.8.0") || ikeTooOld("5.9.1") || ikeTooOld("6.0") || ikeTooOld("") {
		t.Error("ikeTooOld")
	}
}
