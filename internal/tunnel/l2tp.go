package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/ipsec"
	"github.com/Amirhat/riftroute/internal/l2tp"
	"github.com/Amirhat/riftroute/internal/tunneldns"
)

// L2TPEnv is what L2TP/IPsec tunnels run on (docs/tunnels-l2tp.md): L2TP
// and PPP in the daemon (internal/l2tp) over a TUN, IPsec by strongSwan's
// charon (internal/ipsec).
type L2TPEnv struct {
	// IPsec brings each tunnel's IPsec up and down; nil: only tunnels
	// without IPsec run here, and IPsecEngine says why.
	IPsec IPsecRunner
	// IPsecEngine says whether IPsec can run here and how to fix it (nil:
	// it can whenever IPsec is set).
	IPsecEngine func() domain.TunnelEngine
	// System makes the TUN and puts PPP's address on it (nil: this OS's
	// own, as WireGuard's).
	System WGSystem
	// Dial opens the UDP socket to the server's L2TP port (nil: from port
	// 1701, which servers expect, shared with other tunnels' sockets).
	Dial func(ctx context.Context, server netip.AddrPort) (net.Conn, error)
}

// IPsecRunner is ipsec.Charon's part a session uses.
type IPsecRunner interface {
	Up(ctx context.Context, c ipsec.Conn) error
	Down(name string)
}

// l2tpDriver runs L2TP/IPsec connections.
type l2tpDriver struct{ o *Options }

func (l2tpDriver) parse(config string) (*parsed, error) {
	c, err := ParseL2TP(config)
	if err != nil {
		return nil, err
	}
	return &parsed{
		remotes: []Remote{c.Remote}, servers: c.Servers(), ignored: c.Ignored,
		needsAuth: true, inlineUser: c.Username, inlinePass: c.Password,
		l2tp: c,
	}, nil
}

func (d l2tpDriver) env() *L2TPEnv {
	if d.o.L2TP != nil {
		return d.o.L2TP
	}
	return &L2TPEnv{}
}

func (d l2tpDriver) system() WGSystem {
	if s := d.env().System; s != nil {
		return s
	}
	return l2tpSystem()
}

// engine: L2TP and PPP are built in; they need a TUN. IPsec's own engine
// is checked per tunnel (check): one without IPsec doesn't need it.
func (d l2tpDriver) engine() domain.TunnelEngine {
	sys := d.system()
	if sys == nil {
		return domain.TunnelEngine{Problem: "L2TP tunnels run on macOS and Linux"}
	}
	if n, ok := sys.(NoWireGuard); ok {
		return domain.TunnelEngine{Problem: n.Why}
	}
	return domain.TunnelEngine{Available: true, Version: "L2TP and PPP (built in)"}
}

// report is the engine as the daemon reports it: L2TP's, with IPsec's
// (charon) where it's missing — most L2TP tunnels need it.
func (d l2tpDriver) report() domain.TunnelEngine {
	e := d.engine()
	if !e.Available {
		return e
	}
	env := d.env()
	switch {
	case env.IPsec == nil:
		e.Problem = "IPsec for L2TP tunnels isn't available in this daemon (only L2TP without IPsec runs)"
	case env.IPsecEngine != nil:
		if ie := env.IPsecEngine(); !ie.Available {
			e.Problem, e.Install = "L2TP/IPsec needs strongSwan's charon: "+ie.Problem, ie.Install
		} else {
			e.Path, e.Version = ie.Path, e.Version+"; IPsec: "+ie.Version
		}
	}
	return e
}

// check: a tunnel with IPsec needs charon here.
func (d l2tpDriver) check(p *parsed) error {
	if p.l2tp.IPsec == L2TPNoIPsec {
		return nil
	}
	e := d.env()
	if e.IPsec == nil {
		return errors.New("IPsec for L2TP tunnels isn't available in this daemon")
	}
	if e.IPsecEngine != nil {
		if eng := e.IPsecEngine(); !eng.Available {
			msg := "L2TP/IPsec needs strongSwan's charon: " + eng.Problem
			if in := eng.Install; in != nil && len(in.Commands) > 0 {
				msg += " — " + strings.Join(in.Commands, " && ")
			} else if in != nil && in.Note != "" {
				msg += " — " + in.Note
			}
			return errors.New(msg)
		}
	}
	return nil
}

func (d l2tpDriver) run(ctx context.Context, m *Manager, name string, def *def, p *parsed, s *session) {
	(&l2tpSession{m: m, name: name, d: def, c: p.l2tp, s: s, env: d.env(), sys: d.system()}).run(ctx)
}

// L2TP's timing (vars for tests).
var (
	l2tpDialWait = 45 * time.Second // IPsec up, then L2TP and PPP
	l2tpPoll     = time.Second      // counters
)

// l2tpSession is one L2TP tunnel's session: an attempt (IPsec, L2TP, PPP,
// the TUN) at a time, again until the tunnel is stopped.
type l2tpSession struct {
	m    *Manager
	name string
	d    *def
	c    *L2TPConfig
	s    *session
	env  *L2TPEnv
	sys  WGSystem

	remotes  []Remote
	resolved time.Time
	log      ring // max set by run
}

func (k *l2tpSession) run(ctx context.Context) {
	k.log.max = 200
	proc := &l2tpProc{log: &k.log, done: make(chan struct{})}
	k.s.proc.Store(Process(proc))
	defer proc.end()
	if err := k.resolve(ctx); err != nil {
		k.m.setErr(k.name, err.Error())
		return
	}
	rejects := 0 // rejections in a row of a login that had worked
	for attempt := 0; ; attempt++ {
		wasUp, err := k.attempt(ctx, k.remotes[attempt%len(k.remotes)].Host)
		if ctx.Err() != nil || k.s.stopping.Load() {
			return
		}
		var fatal errFatal
		if errors.As(err, &fatal) {
			k.m.setErr(k.name, fatal.msg)
			return
		}
		var rejected errRejected
		switch {
		case errors.As(err, &rejected):
			rejects++
			if rejects > len(ikeRejectWaits) {
				k.m.forgetLogin(k.name)
				k.m.setErr(k.name, fmt.Sprintf("gave up after %d rejections in a row: %s", rejects, rejected.msg))
				return
			}
		case wasUp:
			rejects = 0
		}
		giveUp := false
		var failures int
		k.m.update(k.name, func(r *live) {
			r.state, r.iface, r.detail = domain.TunnelReconnecting, "", "waiting to reconnect"
			r.failures++
			failures = r.failures
			if err != nil {
				r.lastErr = err.Error()
			}
			giveUp = r.since == nil && r.failures >= maxFailedAttempts
		})
		if wasUp {
			k.m.requestApply()
		}
		if giveUp {
			k.m.update(k.name, func(r *live) {
				r.lastErr = fmt.Sprintf("gave up after %d attempts: %s", r.failures, lastLine([]string{r.lastErr}, "no connection"))
			})
			k.m.changed()
			return
		}
		k.m.changed()
		wait := min(ikeBackoffMin<<min(failures-1, 10), ikeBackoffMax)
		if rejects > 0 && errors.As(err, &rejected) {
			wait = ikeRejectWaits[rejects-1]
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if time.Since(k.resolved) >= time.Minute && hasHostname([]Remote{k.c.Remote}) {
			_ = k.resolve(ctx)
		}
	}
}

// resolve picks the server's addresses and pins them (via direct), applying
// that before the first packet, as IKEv2's does.
func (k *l2tpSession) resolve(ctx context.Context) error {
	k.resolved = time.Now()
	remotes, pins, err := k.m.resolveRemotes(ctx, k.d.Via, []Remote{k.c.Remote})
	if err != nil {
		return err
	}
	servers := pins
	if k.d.Via != domain.TunnelViaDirect {
		servers = k.m.serverAddrs(ctx, []Remote{k.c.Remote})
	}
	first := k.remotes == nil
	if !first && sameAddrs(pinsOf(k.m, k.name), pins) {
		return nil
	}
	k.remotes = remotes
	k.m.update(k.name, func(r *live) { r.bypass, r.servers = pins, servers })
	if (len(pins) > 0 || (first && k.d.blocks())) && ctx.Err() == nil {
		if err := k.m.applyAndWait(ctx, 10*time.Second); err != nil {
			k.m.o.Log.Warn("tunnel server not pinned yet; connecting anyway", "tunnel", k.name, "err", err)
		}
	}
	return nil
}

// ipsecName is the tunnel's IPsec connection in charon.
func ipsecName(tunnel string) string { return "rr-" + tunnel }

// attempt is one try: IPsec, L2TP and PPP, then the TUN, until the session
// ends. wasUp: it connected.
func (k *l2tpSession) attempt(ctx context.Context, host string) (wasUp bool, err error) {
	server, err := k.serverAddr(ctx, host)
	if err != nil {
		return false, err
	}
	encrypted := k.c.IPsec != L2TPNoIPsec
	if encrypted {
		conn, err := k.ipsecConn(server)
		if err != nil {
			return false, errFatal{err.Error()}
		}
		k.m.update(k.name, func(r *live) { r.detail = "IPsec" })
		k.m.changed()
		k.log.printf("IPsec to %s (IKEv%d, %s)", server, k.c.IKEVersion, k.c.IPsec)
		ictx, cancel := context.WithTimeout(ctx, l2tpDialWait)
		err = k.env.IPsec.Up(ictx, conn)
		cancel()
		// Down whatever happened: the policies, the SA, the secrets go.
		defer k.env.IPsec.Down(conn.Name)
		if err != nil {
			k.log.printf("IPsec: %v", err)
			if ipsec.Lasting(err) {
				return false, errFatal{err.Error()}
			}
			return false, err
		}
	}
	dial := k.env.Dial
	if dial == nil {
		dial = dialL2TP
	}
	sock, err := dial(ctx, netip.AddrPortFrom(server, 1701))
	if err != nil {
		return false, fmt.Errorf("can't reach the server's L2TP port: %v", err)
	}
	k.m.update(k.name, func(r *live) { r.detail = "L2TP and PPP" })
	k.m.changed()
	user, pass := orString(k.d.Username, k.c.Username), orString(k.d.Password, k.c.Password)
	dctx, cancel := context.WithTimeout(ctx, l2tpDialWait)
	sess, err := l2tp.Dial(dctx, l2tp.Config{
		Conn: sock, Username: user, Password: pass, Encrypted: encrypted,
		Log: k.m.o.Log.With("tunnel", k.name),
	})
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		k.log.printf("L2TP: %v", err)
		lasting, rejected := l2tp.Lasting(err)
		switch {
		case rejected && k.loginWorked():
			return false, errRejected{err.Error()}
		case lasting:
			return false, errFatal{err.Error()}
		}
		return false, err
	}
	defer sess.Close()
	k.log.printf("PPP up: %s, DNS %v, MTU %d", sess.LocalIP(), sess.DNS(), sess.MTU())
	if why := k.up(ctx, sess); why != "" {
		return false, errFatal{why}
	}
	return true, k.carry(ctx, sess)
}

// serverAddr is the address IPsec and L2TP talk to: the pinned one, or the
// name looked up (via default).
func (k *l2tpSession) serverAddr(ctx context.Context, host string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap(), nil
	}
	if k.m.o.Resolve == nil {
		return netip.Addr{}, fmt.Errorf("couldn't resolve %s", host)
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addrs, err := k.m.o.Resolve(rctx, host)
	if err != nil || len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("couldn't resolve %s: %v", host, err)
	}
	for _, a := range addrs {
		if a.Unmap().Is4() {
			return a.Unmap(), nil
		}
	}
	return addrs[0].Unmap(), nil
}

func (k *l2tpSession) ipsecConn(server netip.Addr) (ipsec.Conn, error) {
	conn := ipsec.Conn{
		Name: ipsecName(k.name), Server: server, Version: k.c.IKEVersion,
		LocalID: k.c.LocalID, RemoteID: k.c.RemoteID,
	}
	switch k.c.IPsec {
	case L2TPPSK:
		conn.PSK = k.c.PSK
	case L2TPCertificate:
		key, err := pemKey(k.c.Key)
		if err != nil {
			return conn, fmt.Errorf("couldn't read the profile's private key: %v", err)
		}
		conn.Cert, conn.Key = pemCert(k.c.Cert), key
		for _, c := range k.c.Chain {
			conn.Chain = append(conn.Chain, pemCert(c))
		}
	}
	for _, ca := range k.c.CAs {
		conn.CAs = append(conn.CAs, pemCert(ca))
	}
	return conn, nil
}

// up makes the TUN, vets PPP's address and puts it on, and records the
// tunnel as connected; why says why it's refused.
func (k *l2tpSession) up(ctx context.Context, sess *l2tp.Session) (why string) {
	tdev, err := k.sys.CreateTUN(sess.MTU())
	if err != nil {
		return "couldn't create the tunnel's interface: " + err.Error()
	}
	iface, err := tdev.Name()
	if err != nil {
		_ = tdev.Close()
		return "couldn't name the tunnel's interface: " + err.Error()
	}
	local := sess.LocalIP()
	if why := k.m.vetConfigured(ctx, k.name, iface, hostPrefixes([]netip.Addr{local})); why != "" {
		_ = tdev.Close()
		return why
	}
	if err := k.sys.Configure(ctx, iface, []netip.Addr{local}, sess.MTU()); err != nil {
		_ = tdev.Close()
		return "couldn't set up " + iface + ": " + err.Error()
	}
	k.pump(tdev, sess)
	if k.c.Username != "" || k.d.Username != "" {
		k.m.rememberLogin(k.name, k.loginPrint())
	}
	now := time.Now()
	k.m.update(k.name, func(r *live) {
		r.state, r.detail, r.lastErr, r.failures = domain.TunnelConnected, "", "", 0
		r.iface, r.localIP, r.v6 = iface, local.String(), false
		r.dns, r.dnsWhy = tunneldns.Config{Servers: sess.DNS()}, ""
		if len(sess.DNS()) == 0 {
			r.dnsWhy = "the server gave no DNS servers (IPCP); set some for the tunnel"
		}
		r.server = k.remotes[0].Host
		r.since = &now
	})
	k.m.requestApply()
	k.m.changed()
	return ""
}

// tunOffset is room before each packet for what a TUN puts there (macOS's
// address family, Linux's virtio header).
const tunOffset = 16

// pump carries packets between the TUN and the session until either ends:
// the TUN is closed when the session is.
func (k *l2tpSession) pump(dev tun.Device, sess *l2tp.Session) {
	go func() {
		<-sess.Done()
		_ = dev.Close()
	}()
	go func() { // TUN → server
		bufs := make([][]byte, dev.BatchSize())
		for i := range bufs {
			bufs[i] = make([]byte, tunOffset+65535)
		}
		sizes := make([]int, len(bufs))
		for {
			n, err := dev.Read(bufs, sizes, tunOffset)
			if err != nil {
				if errors.Is(err, tun.ErrTooManySegments) {
					continue
				}
				return
			}
			for i := range n {
				if p := bufs[i][tunOffset : tunOffset+sizes[i]]; len(p) > 0 && p[0]>>4 == 4 {
					_ = sess.WritePacket(p) // IPv4 only: the link carries nothing else
				}
			}
		}
	}()
	go func() { // server → TUN
		for {
			p, err := sess.ReadPacket()
			if err != nil {
				return
			}
			b := make([]byte, tunOffset+len(p))
			copy(b[tunOffset:], p)
			if _, err := dev.Write([][]byte{b}, tunOffset); err != nil && errors.Is(err, os.ErrClosed) {
				return
			}
		}
	}()
}

// carry follows the connected session: its counters, until it ends (why)
// or the tunnel is stopped.
func (k *l2tpSession) carry(ctx context.Context, sess *l2tp.Session) error {
	t := time.NewTicker(l2tpPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-sess.Done():
			err := sess.Err()
			if err == nil {
				err = errors.New("the connection ended")
			}
			k.log.printf("ended: %v", err)
			return err
		case <-t.C:
			rx, tx := sess.Counters()
			k.m.update(k.name, func(r *live) { r.in, r.out = rx, tx })
		}
	}
}

// loginPrint and loginWorked: as IKEv2's (#37: a login that has never
// worked isn't tried twice).
func (k *l2tpSession) loginPrint() string {
	h := sha256.Sum256([]byte(k.d.Config + "\x00" + k.d.Username + "\x00" + k.d.Password))
	return hex.EncodeToString(h[:])
}

func (k *l2tpSession) loginWorked() bool { return k.m.loggedIn(k.name) == k.loginPrint() }

// dialL2TP opens a UDP socket to the server's L2TP port from port 1701,
// which servers expect (Apple's and Windows' clients use it). Other L2TP
// tunnels' sockets share the port: each is connected to its own server, so
// the kernel gives each its own packets.
func dialL2TP(ctx context.Context, server netip.AddrPort) (net.Conn, error) {
	d := net.Dialer{
		LocalAddr: &net.UDPAddr{Port: 1701},
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			err := c.Control(func(fd uintptr) { serr = reusePort(fd) })
			if err != nil {
				return err
			}
			return serr
		},
	}
	return d.DialContext(ctx, "udp", server.String())
}

// l2tpProc is a session's Process: no program of its own (L2TP is in the
// daemon; charon is shared), only its log.
type l2tpProc struct {
	log  *ring
	once sync.Once
	done chan struct{}
}

func (p *l2tpProc) Pid() int       { return os.Getpid() }
func (p *l2tpProc) Wait() error    { <-p.done; return nil }
func (p *l2tpProc) Kill() error    { return nil } // the session's context ends it
func (p *l2tpProc) Tail() []string { return p.log.lines() }
func (p *l2tpProc) end()           { p.once.Do(func() { close(p.done) }) }
