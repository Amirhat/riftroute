// Package dnsproxy is the learning half of wildcard domain rules (spec §5.1
// "*.example.com"): DNS cannot enumerate a wildcard's subdomains, so the
// daemon runs a tiny loopback DNS forwarder and points the wildcard's apex at
// it via split-DNS (macOS /etc/resolver files match a domain AND all its
// subdomains). Every answer that passes through for a matching name teaches
// the engine real subdomain IPs, which the reconciler then routes — so
// app.example.com starts following the rule the moment anything looks it up.
//
// Fail-safe by construction: the proxy only ever FORWARDS to the system's
// real upstream resolvers and relays answers verbatim; learning is a
// read-only tap. If the proxy dies, the daemon removes the resolver files on
// shutdown so DNS falls back to the system path.
package dnsproxy

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	queryTimeout = 3 * time.Second
	maxUDP       = 4096
)

// Learner is invoked (concurrently) when a proxied answer resolves a name
// covered by a wildcard rule.
type Learner func(rule, fqdn string, addrs []netip.Addr)

// Proxy is a loopback DNS forwarder with a learning tap.
type Proxy struct {
	log   *slog.Logger
	learn Learner

	mu        sync.RWMutex
	upstreams []string          // "ip:53"
	apexes    map[string]string // apex → rule value ("*.apex")

	startMu sync.Mutex
	pc      net.PacketConn
	tln     net.Listener
	port    int
	done    chan struct{}
	wg      sync.WaitGroup // in-flight handlers, drained by Stop
	sem     chan struct{}  // bounds concurrent handlers (local-DoS guard)
}

const maxInFlight = 128 // concurrent handler cap (loopback, so generous)

// New builds a stopped proxy. learn may be nil (pure forwarding).
func New(log *slog.Logger, learn Learner) *Proxy {
	if log == nil {
		log = slog.Default()
	}
	return &Proxy{log: log, learn: learn, apexes: map[string]string{}, sem: make(chan struct{}, maxInFlight)}
}

// SetUpstreams installs the REAL resolvers to forward to (":53" added when no
// port is given). Invalid addresses are dropped; the proxy's own address is
// filtered at forward time (self-loop guard) so a legitimate local resolver
// on loopback still works.
func (p *Proxy) SetUpstreams(servers []string) {
	var ups []string
	for _, s := range servers {
		host := s
		if h, _, err := net.SplitHostPort(s); err == nil {
			host = h
		}
		if _, err := netip.ParseAddr(host); err != nil {
			continue
		}
		if host == s {
			s = net.JoinHostPort(s, "53")
		}
		ups = append(ups, s)
	}
	p.mu.Lock()
	p.upstreams = ups
	p.mu.Unlock()
}

// isSelf reports whether up would loop back into this proxy.
func (p *Proxy) isSelf(up string) bool {
	host, port, err := net.SplitHostPort(up)
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(host)
	if err != nil || !a.IsLoopback() {
		return false
	}
	p.startMu.Lock()
	defer p.startMu.Unlock()
	return p.port != 0 && port == itoa(p.port)
}

// SetWildcards installs the wildcard rule values ("*.example.com") whose
// names the proxy should learn.
func (p *Proxy) SetWildcards(rules []string) {
	m := map[string]string{}
	for _, r := range rules {
		apex := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(r, "*."), "."))
		if apex != "" {
			m[apex] = r
		}
	}
	p.mu.Lock()
	p.apexes = m
	p.mu.Unlock()
}

// Apexes returns the currently configured apex domains (resolver-file targets).
func (p *Proxy) Apexes() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, 0, len(p.apexes))
	for a := range p.apexes {
		out = append(out, a)
	}
	return out
}

// Active reports whether the proxy is serving, and on which port.
func (p *Proxy) Active() (bool, int) {
	p.startMu.Lock()
	defer p.startMu.Unlock()
	return p.pc != nil, p.port
}

// Ready reports whether the proxy is serving AND has at least one upstream to
// forward to. Pointing a resolver file at a proxy with no upstream would
// blackhole those domains (it answers every query with silence and macOS
// won't fall back past a scoped resolver), so resolver files are installed
// only when Ready.
func (p *Proxy) Ready() (bool, int) {
	p.startMu.Lock()
	active, port := p.pc != nil, p.port
	p.startMu.Unlock()
	if !active {
		return false, 0
	}
	p.mu.RLock()
	n := len(p.upstreams)
	p.mu.RUnlock()
	return n > 0, port
}

// Start binds UDP and TCP on the same loopback port and serves until Stop.
// Idempotent; returns the bound port.
func (p *Proxy) Start() (int, error) {
	p.startMu.Lock()
	defer p.startMu.Unlock()
	if p.pc != nil {
		return p.port, nil
	}
	var pc net.PacketConn
	var tln net.Listener
	var err error
	// TCP fallback (truncated answers) must live on the SAME port the resolver
	// file names; retry a few times if the paired TCP port is taken.
	for attempt := 0; attempt < 5; attempt++ {
		pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return 0, err
		}
		port := pc.LocalAddr().(*net.UDPAddr).Port
		tln, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(port)))
		if err == nil {
			p.pc, p.tln, p.port = pc, tln, port
			break
		}
		_ = pc.Close()
	}
	if p.pc == nil {
		return 0, err
	}
	p.done = make(chan struct{})
	go p.serveUDP(p.pc, p.done)
	go p.serveTCP(p.tln, p.done)
	p.log.Info("wildcard DNS learner listening", "addr", p.pc.LocalAddr().String())
	return p.port, nil
}

// Stop closes the listeners and drains in-flight handlers. Idempotent.
func (p *Proxy) Stop() {
	p.startMu.Lock()
	if p.pc == nil {
		p.startMu.Unlock()
		return
	}
	close(p.done)
	_ = p.pc.Close()
	_ = p.tln.Close()
	p.pc, p.tln, p.port = nil, nil, 0
	p.startMu.Unlock()
	// Drain OUTSIDE the lock so a handler finishing up can't deadlock against it.
	p.wg.Wait()
}

// spawn runs fn as a bounded handler goroutine: if the in-flight cap is hit the
// packet/connection is dropped rather than growing goroutines unboundedly (a
// local process flooding the loopback port can't exhaust memory/fds). Returns
// false if the work was shed.
func (p *Proxy) spawn(fn func()) bool {
	select {
	case p.sem <- struct{}{}:
	default:
		return false // at capacity — shed load
	}
	p.wg.Add(1)
	go func() {
		defer func() { <-p.sem; p.wg.Done() }()
		fn()
	}()
	return true
}

func (p *Proxy) serveUDP(pc net.PacketConn, done chan struct{}) {
	buf := make([]byte, maxUDP)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-done:
				return
			default:
				continue
			}
		}
		q := make([]byte, n)
		copy(q, buf[:n])
		p.spawn(func() { p.handleUDP(pc, addr, q) })
	}
}

func (p *Proxy) handleUDP(pc net.PacketConn, client net.Addr, query []byte) {
	resp := p.forwardUDP(query)
	if resp == nil {
		return // let the stub resolver time out / retry — never fabricate answers
	}
	_, _ = pc.WriteTo(resp, client)
	p.observe(resp)
}

// forwardUDP relays a query to the first healthy upstream and returns the
// verbatim response bytes (nil if every upstream failed).
func (p *Proxy) forwardUDP(query []byte) []byte {
	p.mu.RLock()
	ups := append([]string(nil), p.upstreams...)
	p.mu.RUnlock()
	for _, up := range ups {
		if p.isSelf(up) {
			continue
		}
		c, err := net.DialTimeout("udp", up, queryTimeout)
		if err != nil {
			continue
		}
		_ = c.SetDeadline(time.Now().Add(queryTimeout))
		if _, err := c.Write(query); err != nil {
			_ = c.Close()
			continue
		}
		buf := make([]byte, maxUDP)
		n, err := c.Read(buf)
		_ = c.Close()
		if err != nil || n == 0 {
			continue
		}
		return buf[:n]
	}
	return nil
}

// serveTCP handles the truncation fallback: one length-prefixed exchange per
// connection, relayed to the first healthy upstream over TCP.
func (p *Proxy) serveTCP(ln net.Listener, done chan struct{}) {
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-done:
				return
			default:
				continue
			}
		}
		if !p.spawn(func() { p.handleTCP(c) }) {
			_ = c.Close() // at capacity — shed
		}
	}
}

func (p *Proxy) handleTCP(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(queryTimeout * 2))
	query, err := readTCPMessage(client)
	if err != nil {
		return
	}
	p.mu.RLock()
	ups := append([]string(nil), p.upstreams...)
	p.mu.RUnlock()
	for _, up := range ups {
		if p.isSelf(up) {
			continue
		}
		u, err := net.DialTimeout("tcp", up, queryTimeout)
		if err != nil {
			continue
		}
		_ = u.SetDeadline(time.Now().Add(queryTimeout))
		if err := writeTCPMessage(u, query); err != nil {
			_ = u.Close()
			continue
		}
		resp, err := readTCPMessage(u)
		_ = u.Close()
		if err != nil {
			continue
		}
		_ = writeTCPMessage(client, resp)
		p.observe(resp)
		return
	}
}

func readTCPMessage(c net.Conn) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(c, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func writeTCPMessage(c net.Conn, msg []byte) error {
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(msg)))
	if _, err := c.Write(l[:]); err != nil {
		return err
	}
	_, err := c.Write(msg)
	return err
}

// CommonSubdomainLabels is the wordlist the daemon proactively resolves under
// each wildcard apex (see prewarm). DNS can't enumerate a wildcard's children,
// so pre-resolving the common ones — done by the daemon itself, independent of
// the browser — means their routes exist BEFORE anything connects, which fixes
// both the first-connection race and the case where the browser resolves over
// DoH (bypassing our scoped resolver entirely).
var CommonSubdomainLabels = []string{
	"www", "app", "api", "api2", "cdn", "static", "assets", "media", "img",
	"images", "files", "download", "ws", "wss", "socket", "stream", "live",
	"feed", "data", "quote", "quotes", "market", "markets", "trade", "trading",
	"chart", "charts", "account", "accounts", "login", "auth", "sso", "oauth",
	"portal", "dashboard", "admin", "my", "m", "mobile", "web", "secure", "pay",
	"payment", "checkout", "status", "edge", "gateway", "node", "backend",
}

// Resolve looks up fqdn's A and AAAA records directly against the configured
// upstreams — bypassing the scoped resolver files, so it can never loop back
// into this proxy. Returns the deduped addresses (nil on failure). Used for
// proactive wildcard pre-warming; the results feed the same learn path as
// passively observed answers.
func (p *Proxy) Resolve(fqdn string) []netip.Addr {
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		q, err := buildDNSQuery(fqdn, qtype)
		if err != nil {
			continue
		}
		resp := p.forwardUDP(q)
		if resp == nil {
			continue
		}
		for _, a := range addrsFromResponse(resp) {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}

func buildDNSQuery(fqdn string, qtype dnsmessage.Type) ([]byte, error) {
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	name, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: qtype, Class: dnsmessage.ClassINET}},
	}
	return msg.Pack()
}

func addrsFromResponse(resp []byte) []netip.Addr {
	var msg dnsmessage.Message
	if err := msg.Unpack(resp); err != nil {
		return nil
	}
	var out []netip.Addr
	for _, ans := range msg.Answers {
		switch rr := ans.Body.(type) {
		case *dnsmessage.AResource:
			out = append(out, netip.AddrFrom4(rr.A))
		case *dnsmessage.AAAAResource:
			out = append(out, netip.AddrFrom16(rr.AAAA))
		}
	}
	return out
}

// observe is the learning tap: if the response answers a name covered by a
// wildcard rule, report its A/AAAA addresses.
func (p *Proxy) observe(resp []byte) {
	if p.learn == nil {
		return
	}
	rule, fqdn, addrs := ParseLearnable(resp, p.matchRule)
	if rule != "" && len(addrs) > 0 {
		p.learn(rule, fqdn, addrs)
	}
}

func (p *Proxy) matchRule(name string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for apex, rule := range p.apexes {
		if name == apex || strings.HasSuffix(name, "."+apex) {
			return rule
		}
	}
	return ""
}

// ParseLearnable extracts (rule, question name, A/AAAA answers) from a raw
// DNS response, using match to map a name to its wildcard rule ("" = skip).
// Pure; exported for tests.
func ParseLearnable(resp []byte, match func(name string) string) (string, string, []netip.Addr) {
	var msg dnsmessage.Message
	if err := msg.Unpack(resp); err != nil || len(msg.Questions) == 0 {
		return "", "", nil
	}
	name := strings.ToLower(strings.TrimSuffix(msg.Questions[0].Name.String(), "."))
	rule := match(name)
	if rule == "" {
		return "", "", nil
	}
	var addrs []netip.Addr
	for _, ans := range msg.Answers {
		switch rr := ans.Body.(type) {
		case *dnsmessage.AResource:
			addrs = append(addrs, netip.AddrFrom4(rr.A))
		case *dnsmessage.AAAAResource:
			addrs = append(addrs, netip.AddrFrom16(rr.AAAA))
		}
	}
	return rule, name, addrs
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
