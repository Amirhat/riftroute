package tunnel

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/Amirhat/riftroute/internal/domain"
)

// WGSystem is what the WireGuard driver needs from the OS: a tun device, and
// its addresses and MTU. The daemon's is the real one (wgSystem, per OS);
// tests use an in-memory tun.
type WGSystem interface {
	// CreateTUN makes a new tun device (utunN on macOS, rrwgN on Linux).
	CreateTUN(mtu int) (tun.Device, error)
	// Configure assigns addrs to iface — each as a single host, so no
	// address mask routes anything by itself — sets its MTU and brings it up.
	Configure(ctx context.Context, iface string, addrs []netip.Addr, mtu int) error
}

// The WireGuard session's timing (vars for tests).
var (
	// wgPoll is how often the device's handshakes and counters are read.
	wgPoll = time.Second
	// wgFirstHandshake: a session that has never completed a handshake by
	// then fails (WireGuard's own REKEY_ATTEMPT_TIME).
	wgFirstHandshake = 90 * time.Second
	// wgRekeyAfter: a handshake older than this is renewed at once, even
	// with no traffic, so an idle tunnel can tell a dead server from a
	// quiet one (REKEY_AFTER_TIME).
	wgRekeyAfter = 120 * time.Second
	// wgNudgeEvery spaces those renewals out.
	wgNudgeEvery = 10 * time.Second
	// wgStaleAfter: no handshake for this long, renewals included, and the
	// tunnel is reconnecting (REJECT_AFTER_TIME: its keys no longer work).
	wgStaleAfter = 180 * time.Second
	// wgReresolveEvery: while reconnecting, endpoints given by name are
	// looked up again this often (their addresses may have moved).
	wgReresolveEvery = 60 * time.Second
)

// defaultMTU is WireGuard's usual tunnel MTU (1500 less its overhead on IPv6).
const defaultMTU = 1420

// wgDriver runs WireGuard connections inside the daemon (wireguard-go): no
// process, no management socket — if the daemon dies, its tun device closes
// with it and the kernel removes the interface and its routes.
type wgDriver struct{ o *Options }

func (w wgDriver) parse(config string) (*parsed, error) {
	c, err := ParseWG(config)
	if err != nil {
		return nil, err
	}
	return &parsed{remotes: c.Remotes(), servers: c.Servers(), ignored: c.Ignored, wg: c}, nil
}

func (w wgDriver) system() WGSystem {
	if w.o.WireGuard != nil {
		return w.o.WireGuard
	}
	return wgSystem()
}

func (w wgDriver) engine() domain.TunnelEngine {
	sys := w.system()
	if sys == nil {
		return domain.TunnelEngine{Problem: "WireGuard tunnels run on macOS and Linux"}
	}
	if n, ok := sys.(NoWireGuard); ok {
		return domain.TunnelEngine{Problem: n.Why}
	}
	return domain.TunnelEngine{Available: true, Version: "wireguard-go (built in)"}
}

// NoWireGuard turns WireGuard tunnels off, saying why: under -provider fake,
// where nothing may touch the host, a WireGuard session would create a real
// interface (OpenVPN gets FakeLauncher there instead).
type NoWireGuard struct{ Why string }

func (n NoWireGuard) CreateTUN(int) (tun.Device, error) { return nil, errors.New(n.Why) }
func (n NoWireGuard) Configure(context.Context, string, []netip.Addr, int) error {
	return errors.New(n.Why)
}

func (w wgDriver) run(ctx context.Context, m *Manager, name string, d *def, p *parsed, s *session) {
	c := p.wg
	eps, bypass, servers, err := m.resolveEndpoints(ctx, d.Via, c.Peers)
	if err != nil {
		m.setErr(name, err.Error())
		return
	}
	m.update(name, func(r *live) { r.bypass, r.servers, r.detail = bypass, servers, "starting WireGuard" })
	if len(bypass) > 0 {
		// Pin the endpoints to the physical gateway before the first packet.
		if err := m.applyAndWait(ctx, 10*time.Second); err != nil {
			m.o.Log.Warn("tunnel endpoints not pinned yet; connecting anyway", "tunnel", name, "err", err)
		}
	}
	if ctx.Err() != nil {
		return
	}

	mtu := c.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	sys := w.system()
	tdev, err := sys.CreateTUN(mtu)
	if err != nil {
		m.setErr(name, "couldn't create the tunnel's interface: "+err.Error())
		return
	}
	iface, err := tdev.Name()
	if err != nil {
		_ = tdev.Close()
		m.setErr(name, "couldn't name the tunnel's interface: "+err.Error())
		return
	}
	log := &ring{max: 200}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), &device.Logger{Verbosef: log.printf, Errorf: log.printf})
	proc := &wgProc{dev: dev, log: log}
	s.proc.Store(Process(proc))
	defer proc.Kill() // closes the device, and with it the interface

	uapi, err := c.UAPI(eps)
	if err == nil {
		err = dev.IpcSet(uapi)
	}
	if err != nil {
		// The error never carries the configuration: it holds the keys.
		m.setErr(name, "WireGuard refused the configuration")
		return
	}
	var hosts []netip.Addr
	for _, a := range c.Addresses {
		hosts = append(hosts, a.Addr())
	}
	if err := sys.Configure(ctx, iface, hosts, mtu); err != nil {
		m.setErr(name, "couldn't set up "+iface+": "+err.Error())
		return
	}
	if err := dev.Up(); err != nil {
		m.setErr(name, "couldn't bring WireGuard up: "+err.Error())
		return
	}
	m.update(name, func(r *live) { r.iface, r.detail = iface, "handshake" })
	m.changed()
	(&wgSession{m: m, name: name, d: d, c: c, s: s, dev: dev, iface: iface, hosts: hosts, eps: eps}).supervise(ctx)
}

// resolveEndpoints picks each peer's endpoint address, and the addresses to
// pin (via direct) and to keep out of every tunnel's routes. A name is
// looked up here: WireGuard takes addresses, and the pins must cover exactly
// the ones it sends to. IPv4 is preferred, as a v4 pin is the one a v4-only
// network can honor.
func (m *Manager) resolveEndpoints(ctx context.Context, via domain.TunnelVia, peers []WGPeer) (eps []netip.AddrPort, pins, servers []netip.Addr, err error) {
	for _, p := range peers {
		var addrs []netip.Addr
		if a, perr := netip.ParseAddr(p.Endpoint.Host); perr == nil {
			addrs = []netip.Addr{a}
		} else if m.o.Resolve != nil {
			rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			addrs, err = m.o.Resolve(rctx, p.Endpoint.Host)
			cancel()
			if err != nil {
				m.o.Log.Warn("tunnel endpoint did not resolve", "host", p.Endpoint.Host, "err", err)
			}
		}
		var pick netip.Addr
		for _, a := range addrs {
			a = a.Unmap()
			if via == domain.TunnelViaDirect && !pinnable(a) {
				// A pin routes the address around every other VPN: never for
				// loopback, link-local, multicast or "any".
				m.o.Log.Warn("tunnel endpoint address not usable; skipped", "host", p.Endpoint.Host, "addr", a)
				continue
			}
			if !pick.IsValid() || (a.Is4() && !pick.Is4()) {
				pick = a
			}
		}
		if !pick.IsValid() {
			return nil, nil, nil, fmt.Errorf("couldn't resolve the endpoint %s to a usable address", p.Endpoint.Host)
		}
		eps = append(eps, netip.AddrPortFrom(pick, uint16(p.Endpoint.Port)))
		if !slices.Contains(servers, pick) {
			servers = append(servers, pick)
		}
	}
	if via == domain.TunnelViaDirect {
		pins = servers
	}
	return eps, pins, servers, nil
}

// wgSession supervises a running device: WireGuard has no connection state of
// its own, so the tunnel's is read from its handshakes.
type wgSession struct {
	m     *Manager
	name  string
	d     *def
	c     *WGConfig
	s     *session
	dev   *device.Device
	iface string
	hosts []netip.Addr
	eps   []netip.AddrPort

	up, vetted     bool
	lastNudge      time.Time
	stale, resolve time.Time // when the tunnel went stale; the last re-resolve
}

func (w *wgSession) supervise(ctx context.Context) {
	start := time.Now()
	w.nudge(start)
	tick := time.NewTicker(wgPoll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		now := time.Now()
		st := readWGStats(w.dev)
		w.m.update(w.name, func(r *live) { r.in, r.out = st.rx, st.tx })
		if !st.latest.After(start) {
			// Never shook hands in this session: WireGuard keeps retrying the
			// handshake (every 5 s) until then.
			if now.Sub(start) > wgFirstHandshake {
				w.m.setErr(w.name, w.noHandshake())
				return
			}
			continue
		}
		if !w.vetted {
			if why := w.m.vetAddressing(ctx, w.name, w.iface, w.hostPrefixes()); why != "" {
				w.m.setErr(w.name, why)
				return
			}
			w.vetted = true
		}
		age := now.Sub(st.latest)
		if age > wgRekeyAfter && now.Sub(w.lastNudge) >= wgNudgeEvery {
			w.nudge(now)
		}
		switch {
		case age < wgStaleAfter && !w.up:
			w.up, w.stale = true, time.Time{}
			w.connected(now, st.endpoint)
		case age >= wgStaleAfter && w.up:
			w.up, w.stale = false, now
			w.m.update(w.name, func(r *live) {
				r.state, r.detail = domain.TunnelReconnecting, "waiting for a handshake"
				r.failures++
			})
			w.m.changed()
		case age >= wgStaleAfter && now.Sub(w.stale) >= wgReresolveEvery && now.Sub(w.resolve) >= wgReresolveEvery:
			w.resolve = now
			w.reresolve(ctx)
		}
	}
}

// connected records a (re)established tunnel and has its routes applied.
func (w *wgSession) connected(now time.Time, endpoint string) {
	var local string
	v6 := false
	for _, a := range w.hosts {
		if a.Is4() && local == "" {
			local = a.String()
		}
		v6 = v6 || a.Is6()
	}
	w.m.update(w.name, func(r *live) {
		r.state, r.detail, r.lastErr, r.failures = domain.TunnelConnected, "", "", 0
		r.iface, r.localIP, r.v6, r.server = w.iface, local, v6, endpoint
		r.since = &now
	})
	w.m.requestApply()
	w.m.changed()
}

// nudge starts a handshake with every peer. A keepalive wouldn't do: sent on
// keys still within REJECT_AFTER_TIME, it goes out on them to a server that
// may have lost them (restarted), and nothing answers. WireGuard spaces the
// initiations out (REKEY_TIMEOUT) and retries them on its own.
func (w *wgSession) nudge(now time.Time) {
	w.lastNudge = now
	for _, p := range w.c.Peers {
		if peer := w.dev.LookupPeer(device.NoisePublicKey(p.PublicKey)); peer != nil {
			_ = peer.SendHandshakeInitiation(false)
		}
	}
}

func (w *wgSession) hostPrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, a := range w.hosts {
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out
}

// noHandshake explains a session that never shook hands.
func (w *wgSession) noHandshake() string {
	msg := "no handshake with the server in " + wgFirstHandshake.String() + ": it doesn't answer this key " +
		"(check the configuration's PublicKey and the server's list of peers), or it can't be reached"
	if w.d.Via == domain.TunnelViaDirect {
		msg += " directly — another VPN's firewall (e.g. Windscribe's) may be blocking traffic outside its " +
			"tunnel; allow the endpoint there, or reach it through the main VPN (--via default)"
	}
	return msg
}

// reresolve looks the endpoints given by name up again for a tunnel that has
// stopped shaking hands, and points the device at the new addresses (and
// the pins with them) when they moved — no restart needed.
func (w *wgSession) reresolve(ctx context.Context) {
	if !hasHostname(w.c.Remotes()) {
		return
	}
	eps, pins, servers, err := w.m.resolveEndpoints(ctx, w.d.Via, w.c.Peers)
	if err != nil || slices.Equal(eps, w.eps) {
		return
	}
	var b strings.Builder
	for i, p := range w.c.Peers {
		if eps[i] != w.eps[i] {
			fmt.Fprintf(&b, "public_key=%s\nupdate_only=true\nendpoint=%s\n", hex.EncodeToString(p.PublicKey[:]), eps[i])
		}
	}
	w.m.o.Log.Info("tunnel endpoint addresses changed", "tunnel", w.name)
	w.m.update(w.name, func(r *live) { r.bypass, r.servers = pins, servers })
	if len(pins) > 0 {
		_ = w.m.applyAndWait(ctx, 10*time.Second)
	}
	if err := w.dev.IpcSet(b.String()); err != nil {
		w.m.o.Log.Warn("couldn't point the tunnel at its new endpoint", "tunnel", w.name)
		return
	}
	w.eps = eps
	w.nudge(time.Now())
}

// wgStats is what the device reports: the newest handshake of any peer (and
// that peer's endpoint), and the bytes through all of them.
type wgStats struct {
	latest   time.Time
	endpoint string
	rx, tx   uint64
}

func readWGStats(dev *device.Device) wgStats {
	var st wgStats
	text, err := dev.IpcGet()
	if err != nil {
		return st
	}
	var sec, nsec int64
	var endpoint string
	flush := func() {
		if sec == 0 && nsec == 0 {
			return
		}
		if t := time.Unix(sec, nsec); t.After(st.latest) {
			st.latest, st.endpoint = t, endpoint
		}
	}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		switch k {
		case "public_key":
			flush()
			sec, nsec, endpoint = 0, 0, ""
		case "endpoint":
			endpoint = v
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			n, _ := strconv.ParseUint(v, 10, 64)
			st.rx += n
		case "tx_bytes":
			n, _ := strconv.ParseUint(v, 10, 64)
			st.tx += n
		}
	}
	flush()
	return st
}

// wgProc stands in for a process: the Manager reads the session's log from
// it, and a stop that times out kills it — here, closes the device.
type wgProc struct {
	dev  *device.Device
	log  *ring
	once sync.Once
}

func (p *wgProc) Pid() int { return os.Getpid() } // no process of its own: nothing to reap
func (p *wgProc) Wait() error {
	<-p.dev.Wait()
	return nil
}
func (p *wgProc) Kill() error {
	p.once.Do(p.dev.Close)
	return nil
}
func (p *wgProc) Tail() []string { return p.log.lines() }

// ring keeps the last lines of a session's log.
type ring struct {
	mu  sync.Mutex
	max int
	buf []string
}

func (r *ring) printf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, time.Now().Format("15:04:05 ")+line)
	if len(r.buf) > r.max {
		r.buf = slices.Delete(r.buf, 0, len(r.buf)-r.max)
	}
}

func (r *ring) lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.buf)
}
