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
// openvpn's and charon's own idea of "connected", doesn't show it. So while
// one is connected, something is asked through it every aliveEvery: its
// DNS servers (a query, any answer), else a connection to aliveTargets,
// which its quarters carry. After aliveMisses in a row its session ends,
// failed and saying why. Its routes then leave (fallback) or are refused
// (block), and the system's DNS comes back.
var (
	aliveEvery   = 10 * time.Second
	aliveMisses  = 3
	aliveTimeout = 3 * time.Second
	aliveTargets = []netip.AddrPort{netip.MustParseAddrPort("1.0.0.1:443"), netip.MustParseAddrPort("8.8.4.4:443")}
)

// Prober reports whether traffic gets through a full tunnel: dns are the
// DNS servers in use through it (maybe none).
type Prober func(ctx context.Context, dns []netip.Addr) bool

// probeThrough is the real Prober. The addresses' routes take the probes
// into the tunnel: its DNS servers have host routes into it, and the
// targets are in its quarters (not 1.1.1.1, the watchdog's anchor, which
// is kept out).
func probeThrough(ctx context.Context, dns []netip.Addr) bool {
	for _, a := range dns[:min(len(dns), 2)] {
		if askDNS(ctx, a) {
			return true
		}
	}
	for _, t := range aliveTargets {
		d := net.Dialer{Timeout: aliveTimeout}
		if c, err := d.DialContext(ctx, "tcp", t.String()); err == nil {
			_ = c.Close()
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

// watchAlive probes every connected full tunnel until the manager closes.
func (m *Manager) watchAlive() {
	t := time.NewTicker(aliveEvery)
	defer t.Stop()
	for {
		select {
		case <-m.closed:
			return
		case <-t.C:
			m.probeFull()
		}
	}
}

// probeFull asks through each connected full tunnel once, and ends the
// session of one that missed aliveMisses times in a row.
func (m *Manager) probeFull() {
	type target struct {
		name string
		s    *session
		dns  []netip.Addr
	}
	var ts []target
	m.mu.Lock()
	for name, r := range m.rt {
		if d := m.defs[name]; d != nil && d.AllTraffic && r.sess != nil && r.state == domain.TunnelConnected && r.iface != "" {
			ts = append(ts, target{name, r.sess, slices.Clone(r.dnsInUse)})
		} else {
			r.misses = 0
		}
	}
	m.mu.Unlock()
	for _, t := range ts {
		ctx, cancel := context.WithTimeout(context.Background(), aliveEvery-time.Second)
		ok := m.o.Probe(ctx, t.dns)
		cancel()
		end := false
		m.mu.Lock()
		if r := m.rt[t.name]; r != nil && r.sess == t.s {
			if ok {
				r.misses = 0
			} else if r.misses++; r.misses >= aliveMisses {
				end = true
				r.misses = 0
				r.lastErr = "connected, but nothing got through it for " + (time.Duration(aliveMisses) * aliveEvery).String() +
					" (its server shakes hands but forwards nothing?); ended so this machine isn't cut off: connect it again once the server works"
			}
		}
		m.mu.Unlock()
		if end {
			m.o.Log.Warn("full tunnel passes no traffic; ending it", "tunnel", t.name)
			t.s.cancel() // not stopping: it ends failed, still wanted (block keeps blocking)
		}
	}
}
