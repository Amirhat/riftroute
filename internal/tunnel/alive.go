package tunnel

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// A full tunnel carries everything, so one that's connected but passes no
// traffic cuts this machine off. Its server may shake hands and forward
// nothing (the owner's Mac, 2026-10-27, needed a restart). A handshake, or
// openvpn's and charon's own idea of "connected", doesn't show it, and the
// watchdog's anchors are kept out of the tunnel. So every at.every, for
// each connected full tunnel:
//   - traffic coming back (at.rx since the last look) is proof of life:
//     nothing is asked;
//   - else its DNS servers are asked through it (any answer). These are the
//     ones in use, its server's, or the ones set for it: each was given by
//     the tunnel itself, not the internet beyond it, so a full tunnel into
//     an intranet passes too;
//   - with none known, it's judged by its counters alone: traffic going in
//     (at.tx) and nothing coming back.
//
// A miss counts only while this machine's own path out is up (a default
// route that isn't a tunnel's): asleep, rejoining Wi-Fi or between
// networks, nothing gets through anything. After at.misses in a row, the
// session is reconnected, as a dropped one is. It ends, still wanted, so
// block keeps blocking. It starts again after a wait that doubles from
// first to max while it keeps dying, and is reset by settled of life.
type aliveTimes struct {
	every      time.Duration
	misses     int
	rx, tx     uint64
	settled    time.Duration
	first, max time.Duration
}

// defaultAlive are the manager's (a test's own are its manager's: at).
var defaultAlive = aliveTimes{
	every: 10 * time.Second, misses: 3, rx: 1024, tx: 3 * 1024,
	settled: 2 * time.Minute, first: 5 * time.Second, max: 5 * time.Minute,
}

// aliveTimeout bounds one DNS question through a tunnel.
const aliveTimeout = 3 * time.Second

// Prober reports whether one of a full tunnel's DNS servers answers through
// it.
type Prober func(ctx context.Context, dns []netip.Addr) bool

// probeThrough is the real Prober: the servers' host routes take the
// queries into the tunnel.
func probeThrough(ctx context.Context, dns []netip.Addr) bool {
	for _, a := range dns[:min(len(dns), 3)] {
		if askDNS(ctx, a) {
			return true
		}
	}
	return false
}

// askDNS sends a DNS query for the root's name servers to server: any
// answer, even a refusal, came back through the tunnel.
func askDNS(ctx context.Context, server netip.Addr) bool {
	d := net.Dialer{Timeout: aliveTimeout}
	c, err := d.DialContext(ctx, "udp", netip.AddrPortFrom(server, 53).String())
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(aliveTimeout))
	q := []byte{0x52, 0x52, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1} // ". NS IN", RD
	if _, err := c.Write(q); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	return err == nil && n >= 12 && buf[0] == q[0] && buf[1] == q[1]
}

// liveness is a full tunnel's, kept with its live state.
type liveness struct {
	sess          *session // the session it's about
	in, out       uint64   // the counters at the last look
	misses        int
	lifeSince     time.Time     // when it was last seen alive after a miss
	wait          time.Duration // before the next reconnect (doubling)
	reconnectHint string        // why it's reconnecting, for the card
}

// watchAlive looks at every connected full tunnel, every every, until the
// manager closes.
func (m *Manager) watchAlive(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-m.closed:
			return
		case <-t.C:
			m.lookAlive(time.Now())
		}
	}
}

// outsideUp reports whether this machine has a way out of its own: a
// default route that isn't into one of RiftRoute's tunnels. Without one
// (asleep, between networks) a probe proves nothing.
func (m *Manager) outsideUp(ctx context.Context, tunnels []string) bool {
	if m.o.Routes == nil {
		return true
	}
	rs, err := m.o.Routes(ctx)
	if err != nil {
		return true // can't tell: judge by the probe
	}
	for _, r := range rs {
		if p, err := netip.ParsePrefix(r.DstCIDR); err == nil && p.Bits() == 0 && !r.Reject && !slices.Contains(tunnels, r.Iface) {
			return true
		}
	}
	return false
}

// lookAlive looks at each connected full tunnel once, and reconnects one
// that missed at.misses times in a row.
func (m *Manager) lookAlive(now time.Time) {
	type target struct {
		name    string
		s       *session
		dns     []netip.Addr
		in, out uint64
		a       liveness
	}
	var ts []target
	var ifaces []string
	m.mu.Lock()
	for name, r := range m.rt {
		if r.iface != "" {
			ifaces = append(ifaces, r.iface)
		}
		d := m.defs[name]
		if d == nil || !d.AllTraffic || r.sess == nil || r.state != domain.TunnelConnected || r.iface == "" {
			continue
		}
		if r.alive.sess != r.sess { // a new session: start from its counters
			r.alive = liveness{sess: r.sess, in: r.in, out: r.out, wait: r.alive.wait, lifeSince: now}
			continue
		}
		dns := slices.Clone(r.dnsInUse)
		dns = addAddrs(dns, r.dns.Servers...)
		dns = addAddrs(dns, parseAddrs(d.DNS)...)
		ts = append(ts, target{name, r.sess, dns, r.in, r.out, r.alive})
	}
	m.mu.Unlock()

	at := m.at
	ctx, cancel := context.WithTimeout(context.Background(), at.every*9/10)
	defer cancel()
	up := -1 // the outside's path, looked at once, when a miss needs it
	for _, t := range ts {
		a := t.a
		var dIn, dOut uint64 // a counter that went back (the engine's restart) gives none
		if t.in >= a.in {
			dIn = t.in - a.in
		}
		if t.out >= a.out {
			dOut = t.out - a.out
		}
		a.in, a.out = t.in, t.out
		alive, judged := dIn >= at.rx, true
		if !alive {
			if len(t.dns) > 0 {
				alive = m.o.Probe(ctx, t.dns)
			} else {
				judged = dOut >= at.tx // going in, nothing back
			}
		}
		if !alive && judged && up < 0 {
			up = 0
			if m.outsideUp(ctx, ifaces) {
				up = 1
			}
		}
		reconnect := false
		switch {
		case alive:
			a.misses = 0
			if now.Sub(a.lifeSince) >= at.settled {
				a.wait = 0 // it's stayed alive: the next death starts the waits over
			}
		case !judged, up == 0:
			// Nothing to judge, or this machine's own way out is down.
		default:
			a.lifeSince = now
			if a.misses++; a.misses >= at.misses {
				reconnect = true
				a.misses = 0
				a.wait = min(max(a.wait*2, at.first), at.max)
			}
		}
		m.mu.Lock()
		r := m.rt[t.name]
		if r == nil || r.sess != t.s {
			m.mu.Unlock()
			continue
		}
		if reconnect {
			a.reconnectHint = "connected, but nothing got through it for " + (time.Duration(at.misses) * at.every).String() +
				" (its server shakes hands but forwards nothing?); reconnecting in " + a.wait.String()
			r.lastErr = a.reconnectHint
		}
		r.alive = a
		m.mu.Unlock()
		if reconnect {
			m.o.Log.Warn("full tunnel passes no traffic; reconnecting it", "tunnel", t.name, "in", a.wait)
			t.s.cancel() // not stopping: it ends failed, still wanted (block keeps blocking)
			time.AfterFunc(a.wait, func() { m.reconnectDead(t.name) })
		}
	}
}

// reconnectDead connects a full tunnel again after its dead session ended,
// unless it's no longer wanted, or something else connected it meanwhile.
func (m *Manager) reconnectDead(name string) {
	m.mu.Lock()
	r := m.rt[name]
	again := r != nil && r.want && r.sess == nil && !r.deleting && !m.isClosed()
	m.mu.Unlock()
	if again {
		if err := m.Connect(name); err != nil {
			m.o.Log.Warn("full tunnel not reconnected", "tunnel", name, "err", err)
		}
	}
}
