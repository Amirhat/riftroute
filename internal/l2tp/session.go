package l2tp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

// isRefused: the server's port answered with ICMP port unreachable.
func isRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

// Config is one connection's.
type Config struct {
	// Conn is a UDP socket connected to the server's L2TP port (1701). The
	// session owns it from Dial on, and closes it.
	Conn net.Conn
	// Username and Password are the PPP login.
	Username, Password string
	// Encrypted: IPsec protects Conn. Without it, a server that asks for
	// PAP (the password in the clear) is refused.
	Encrypted bool
	// HostName is sent to the server (default "riftroute").
	HostName string
	// MRU is the largest packet we take (default 1400).
	MRU int
	Log *slog.Logger
}

// Session is an established L2TP session with PPP up: IPv4 packets in and
// out.
type Session struct {
	conn               net.Conn
	peerTunnel, peerSs uint16 // what our data messages carry
	local, peer        netip.Addr
	dns                []netip.Addr
	mtu                int

	in   chan []byte // IPv4 packets from the server
	done chan struct{}
	once sync.Once
	err  error
	stop chan struct{} // Close
	stat struct {
		sync.Mutex
		rx, tx uint64
	}
	bufs sync.Pool
}

// Timing, variables for tests.
var (
	ctlFirst   = time.Second     // the first retransmission
	ctlMax     = 8 * time.Second // the longest wait between them
	ctlTries   = 5               // retransmissions before giving up
	helloEvery = 60 * time.Second
	authWait   = 30 * time.Second
	tick       = 200 * time.Millisecond
)

// Dial sets up the L2TP tunnel and session and brings PPP up: it returns
// once IPCP has given this end its address, or fails with why.
func Dial(ctx context.Context, cfg Config) (*Session, error) {
	if cfg.Conn == nil {
		return nil, errors.New("l2tp: no socket")
	}
	if cfg.HostName == "" {
		cfg.HostName = "riftroute"
	}
	if cfg.MRU == 0 {
		cfg.MRU = 1400
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	s := &Session{conn: cfg.Conn, in: make(chan []byte, 256), done: make(chan struct{}), stop: make(chan struct{})}
	s.bufs.New = func() any { b := make([]byte, 0, 2048); return &b }
	l := newLoop(s, cfg)
	up := make(chan struct{})
	go l.run(up)
	select {
	case <-up:
		return s, nil
	case <-s.done:
		return nil, s.err
	case <-ctx.Done():
		_ = s.Close()
		<-s.done
		return nil, ctx.Err()
	}
}

// LocalIP is this end's address (IPCP's).
func (s *Session) LocalIP() netip.Addr { return s.local }

// PeerIP is the server's end of the link, when it said.
func (s *Session) PeerIP() netip.Addr { return s.peer }

// DNS are the servers IPCP gave (RFC 1877), maybe none.
func (s *Session) DNS() []netip.Addr { return s.dns }

// MTU is the largest IP packet to send.
func (s *Session) MTU() int { return s.mtu }

// Done is closed when the session has ended; Err says why.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err is why the session ended (nil after Close).
func (s *Session) Err() error {
	select {
	case <-s.done:
		return s.err
	default:
		return nil
	}
}

// Counters are the bytes of IP packets received and sent.
func (s *Session) Counters() (rx, tx uint64) {
	s.stat.Lock()
	defer s.stat.Unlock()
	return s.stat.rx, s.stat.tx
}

// ReadPacket returns the next IPv4 packet from the server.
func (s *Session) ReadPacket() ([]byte, error) {
	select {
	case p := <-s.in:
		return p, nil
	case <-s.done:
		if s.err != nil {
			return nil, s.err
		}
		return nil, io.EOF
	}
}

// WritePacket sends an IPv4 packet to the server.
func (s *Session) WritePacket(pkt []byte) error {
	select {
	case <-s.done:
		return net.ErrClosed
	default:
	}
	bp := s.bufs.Get().(*[]byte)
	b := append((*bp)[:0], make([]byte, dataHeaderLen+pppHeaderLen)...)
	putDataHeader(b, s.peerTunnel, s.peerSs)
	putPPPHeader(b[dataHeaderLen:], protoIPv4)
	b = append(b, pkt...)
	_, err := s.conn.Write(b)
	*bp = b
	s.bufs.Put(bp)
	if err == nil {
		s.stat.Lock()
		s.stat.tx += uint64(len(pkt))
		s.stat.Unlock()
	}
	return err
}

// Close ends the session, telling the server (CDN, StopCCN).
func (s *Session) Close() error {
	s.once.Do(func() { close(s.stop) })
	<-s.done
	return nil
}

// --- the loop: one goroutine owns all protocol state ---

type pending struct {
	ns    uint16
	pkt   []byte
	at    time.Time
	wait  time.Duration
	tries int
}

type phase int

const (
	phTunnel  phase = iota // SCCRQ sent
	phSession              // ICRQ sent
	phLCP
	phAuth
	phIPCP
	phUp
)

type loop struct {
	s   *Session
	cfg Config
	log *slog.Logger

	ph                 phase
	ourTunnel, ourSess uint16
	ns, nr             uint16
	queue              []pending
	ack                bool // a ZLB is owed
	lastHeard          time.Time
	heard              bool // the server answered at all

	lcp, ipcp *ncp
	magic     []byte
	peerMRU   int

	auth     uint16 // the protocol the server asked for (0: none)
	chapAlg  byte
	authDone bool
	authAt   time.Time
	papID    uint8
	papNext  time.Time
	papTries int
	chap     struct {
		id                    uint8
		challenge, peer, resp []byte
	}
	protoRejID uint8
	// papRefused: the server asked for PAP, refused for want of IPsec.
	papRefused bool
}

func newLoop(s *Session, cfg Config) *loop {
	l := &loop{s: s, cfg: cfg, log: cfg.Log}
	l.ourTunnel = nonzero16()
	l.ourSess = nonzero16()
	l.magic = make([]byte, 4)
	_, _ = rand.Read(l.magic)
	l.lcp = &ncp{proto: protoLCP, name: "LCP",
		ours: []option{{typ: lcpMRU, data: binary.BigEndian.AppendUint16(nil, uint16(cfg.MRU))}, {typ: lcpMagic, data: l.magic}},
		peer: l.lcpPeer, nak: l.lcpNak, rej: l.lcpRej}
	zero := []byte{0, 0, 0, 0}
	l.ipcp = &ncp{proto: protoIPCP, name: "IPCP",
		ours: []option{{typ: ipcpAddress, data: zero}, {typ: ipcpDNS1, data: zero}, {typ: ipcpDNS2, data: zero}},
		peer: l.ipcpPeer, nak: l.ipcpNak, rej: l.ipcpRej}
	return l
}

func nonzero16() uint16 {
	var b [2]byte
	for {
		_, _ = rand.Read(b[:])
		if v := binary.BigEndian.Uint16(b[:]); v != 0 {
			return v
		}
	}
}

func (l *loop) run(up chan struct{}) {
	s := l.s
	pkts := make(chan []byte, 256)
	readErr := make(chan error, 1)
	go func() {
		for {
			b := make([]byte, 2048)
			n, err := s.conn.Read(b)
			if err != nil {
				readErr <- err
				return
			}
			pkts <- b[:n]
		}
	}()
	t := time.NewTicker(tick)
	defer t.Stop()
	err := l.start()
	for err == nil {
		select {
		case b := <-pkts:
			err = l.input(b, time.Now())
		case e := <-readErr:
			err = l.readFailed(e)
		case now := <-t.C:
			err = l.timers(now)
		case <-s.stop:
			l.hangUp()
			err = errClosed
		}
		if err == nil {
			err = l.flushAck()
		}
		if err == nil && l.ph == phUp && up != nil {
			close(up)
			up = nil
		}
	}
	if !errors.Is(err, errClosed) {
		l.log.Info("l2tp session ended", "err", err)
		l.hangUp()
	} else {
		err = nil
	}
	s.err = err
	_ = s.conn.Close()
	close(s.done)
}

var errClosed = errors.New("closed")

// errPAPInClear: the server takes only PAP, which sends the password as it
// is, and nothing encrypts the connection.
var errPAPInClear = errors.New("the server accepts only PAP, which sends the password unencrypted, and this tunnel has no IPsec: RiftRoute won't send it")

// readFailed: the socket failed. A refused port (ICMP) means nothing
// listens there.
func (l *loop) readFailed(err error) error {
	if errors.Is(err, net.ErrClosed) {
		return errClosed
	}
	if isRefused(err) {
		return fmt.Errorf("can't reach the server's L2TP port: %v", err)
	}
	return fmt.Errorf("l2tp: %v", err)
}

func (l *loop) write(b []byte) error {
	_, err := l.s.conn.Write(b)
	if err != nil && isRefused(err) {
		return nil // the read side reports it
	}
	return err
}

// sendCtl sends a control message reliably.
func (l *loop) sendCtl(session uint16, avps []avp) error {
	peer := l.s.peerTunnel
	pkt := controlPacket(peer, session, l.ns, l.nr, avps)
	l.queue = append(l.queue, pending{ns: l.ns, pkt: pkt, at: time.Now(), wait: ctlFirst})
	l.ns++
	l.ack = false // it carries the acknowledgement
	l.log.Debug("l2tp send", "msg", msgName(binary.BigEndian.Uint16(avps[0].value)))
	return l.write(pkt)
}

func (l *loop) flushAck() error {
	if !l.ack {
		return nil
	}
	l.ack = false
	return l.write(controlPacket(l.s.peerTunnel, 0, l.ns, l.nr, nil))
}

func (l *loop) start() error {
	return l.sendCtl(0, []avp{
		u16AVP(avpMessageType, msgSCCRQ),
		u16AVP(avpProtocolVersion, 0x0100),
		{mandatory: true, typ: avpHostName, value: []byte(l.cfg.HostName)},
		u32AVP(avpFramingCaps, 3), // synchronous and asynchronous
		u16AVP(avpAssignedTunnelID, l.ourTunnel),
		u16AVP(avpReceiveWindow, 4),
		{typ: avpVendorName, value: []byte("RiftRoute")},
	})
}

// hangUp tells the server we're leaving (best effort, not waited for).
func (l *loop) hangUp() {
	if l.s.peerTunnel == 0 {
		return
	}
	if l.ph >= phLCP {
		_ = l.sendPPP(protoLCP, cp{code: codeTermReq, id: 1})
		_ = l.sendCtl(l.s.peerSs, []avp{u16AVP(avpMessageType, msgCDN),
			{mandatory: true, typ: avpResultCode, value: []byte{0, 3}}, // administrative
			u16AVP(avpAssignedSession, l.ourSess)})
	}
	_ = l.sendCtl(0, []avp{u16AVP(avpMessageType, msgStopCCN),
		u16AVP(avpAssignedTunnelID, l.ourTunnel),
		{mandatory: true, typ: avpResultCode, value: []byte{0, 1}}}) // general request
}

func (l *loop) timers(now time.Time) error {
	for i := range l.queue {
		p := &l.queue[i]
		if now.Sub(p.at) < p.wait {
			continue
		}
		if p.tries >= ctlTries {
			if !l.heard {
				return fmt.Errorf("the server didn't answer: nothing came back from %s on UDP port 1701", l.s.conn.RemoteAddr())
			}
			return errors.New("the server stopped answering the L2TP control connection")
		}
		p.tries++
		p.at = now
		p.wait = min(p.wait*2, ctlMax)
		// Resent as it was, but with the current Nr.
		binary.BigEndian.PutUint16(p.pkt[10:], l.nr)
		if err := l.write(p.pkt); err != nil {
			return err
		}
	}
	if l.ph == phUp && len(l.queue) == 0 && now.Sub(l.lastHeard) >= helloEvery {
		if err := l.sendCtl(0, []avp{u16AVP(avpMessageType, msgHello)}); err != nil {
			return err
		}
	}
	if l.ph >= phLCP && l.ph < phUp {
		for _, n := range []*ncp{l.lcp, l.ipcp} {
			if n == l.ipcp && l.ph < phIPCP {
				continue
			}
			again, err := n.due(now)
			if err != nil {
				return err
			}
			if again {
				if err := l.sendPPP(n.proto, n.request(now)); err != nil {
					return err
				}
			}
		}
	}
	if l.ph == phAuth {
		if now.Sub(l.authAt) > authWait {
			return errors.New("the server never finished the login (PPP authentication)")
		}
		if l.auth == protoPAP && now.After(l.papNext) {
			if err := l.sendPAP(now); err != nil {
				return err
			}
		}
	}
	return nil
}

func (l *loop) input(b []byte, now time.Time) error {
	m, err := parse(b)
	if err != nil {
		l.log.Debug("l2tp: dropped a packet", "err", err)
		return nil
	}
	if m.tunnel != l.ourTunnel {
		return nil // not ours
	}
	if !m.control {
		if m.session != l.ourSess || l.ph < phLCP {
			return nil
		}
		return l.ppp(m.payload, now)
	}
	l.heard = true
	l.lastHeard = now
	// Its Nr acknowledges ours.
	for len(l.queue) > 0 && seqLess(l.queue[0].ns, m.nr) {
		l.queue = l.queue[1:]
	}
	if len(m.avps) == 0 { // ZLB
		return nil
	}
	switch {
	case m.ns == l.nr:
		l.nr++
		l.ack = true
	case seqLess(m.ns, l.nr): // a retransmission we've had: acknowledge again
		l.ack = true
		return nil
	default:
		return nil // ahead of a lost one: it's resent
	}
	for _, a := range m.avps {
		if a.hidden {
			return errors.New("the server hides its L2TP attributes (a tunnel secret), which RiftRoute doesn't support")
		}
		if a.mandatory && a.vendor != 0 && m.msgType() != msgStopCCN && m.msgType() != msgCDN {
			return fmt.Errorf("the server sent an L2TP attribute RiftRoute doesn't know (vendor %d, type %d)", a.vendor, a.typ)
		}
	}
	return l.control(m)
}

func (l *loop) control(m *message) error {
	t := m.msgType()
	l.log.Debug("l2tp recv", "msg", msgName(t))
	switch t {
	case msgSCCRP:
		if l.ph != phTunnel {
			return nil
		}
		if _, ok := m.find(avpChallenge); ok {
			return errors.New("the server asks for an L2TP tunnel secret, which RiftRoute doesn't support")
		}
		a, ok := m.find(avpAssignedTunnelID)
		id, err := a.u16()
		if !ok || err != nil || id == 0 {
			return errors.New("the server's L2TP reply carries no tunnel ID")
		}
		l.s.peerTunnel = id
		if err := l.sendCtl(0, []avp{u16AVP(avpMessageType, msgSCCCN)}); err != nil {
			return err
		}
		l.ph = phSession
		return l.sendCtl(0, []avp{
			u16AVP(avpMessageType, msgICRQ),
			u16AVP(avpAssignedSession, l.ourSess),
			u32AVP(avpCallSerial, 1),
		})
	case msgICRP:
		if l.ph != phSession || m.session != l.ourSess {
			return nil
		}
		a, ok := m.find(avpAssignedSession)
		id, err := a.u16()
		if !ok || err != nil || id == 0 {
			return errors.New("the server's L2TP reply carries no session ID")
		}
		l.s.peerSs = id
		if err := l.sendCtl(id, []avp{
			u16AVP(avpMessageType, msgICCN),
			u32AVP(avpTxConnectSpeed, 100000000),
			u32AVP(avpFramingType, 1), // synchronous
		}); err != nil {
			return err
		}
		l.ph = phLCP
		return l.sendPPP(protoLCP, l.lcp.request(time.Now()))
	case msgStopCCN:
		return fmt.Errorf("the server closed the L2TP tunnel%s", resultText(m))
	case msgCDN:
		return fmt.Errorf("the server ended the L2TP session%s", resultText(m))
	case msgHello, msgSCCCN, msgWEN, msgSLI:
		return nil
	case msgSCCRQ, msgICRQ:
		return fmt.Errorf("the server sent an L2TP %s, which only a client sends", msgName(t))
	}
	return nil
}

// resultText is a StopCCN's or CDN's result, for the user.
func resultText(m *message) string {
	code, ec, text := resultCode(m)
	if code == 0 && text == "" {
		return ""
	}
	out := fmt.Sprintf(" (result %d", code)
	if ec != 0 {
		out += fmt.Sprintf(", error %d", ec)
	}
	if text != "" {
		out += ": " + text
	}
	return out + ")"
}

// --- PPP ---

func (l *loop) sendPPP(proto uint16, c cp) error {
	b := make([]byte, dataHeaderLen+pppHeaderLen, dataHeaderLen+pppHeaderLen+4+len(c.data))
	putDataHeader(b, l.s.peerTunnel, l.s.peerSs)
	putPPPHeader(b[dataHeaderLen:], proto)
	return l.write(append(b, c.bytes()...))
}

func (l *loop) ppp(frame []byte, now time.Time) error {
	proto, info, err := pppFrame(frame)
	if err != nil {
		return nil
	}
	switch proto {
	case protoIPv4:
		if l.ph != phUp {
			return nil
		}
		p := make([]byte, len(info))
		copy(p, info)
		l.s.stat.Lock()
		l.s.stat.rx += uint64(len(p))
		l.s.stat.Unlock()
		select {
		case l.s.in <- p:
		default: // nobody reads fast enough: dropped, as a link would
		}
		return nil
	case protoLCP:
		c, err := parseCP(info)
		if err != nil {
			return nil
		}
		switch c.code {
		case codeEchoReq:
			return l.sendPPP(protoLCP, cp{code: codeEchoReply, id: c.id, data: append(append([]byte{}, l.magic...), tail4(c.data)...)})
		case codeProtoRej:
			if len(c.data) >= 2 && binary.BigEndian.Uint16(c.data) == protoIPCP {
				return errors.New("the server refuses IPv4 (IPCP) on this link")
			}
			return nil
		}
		out, err := l.lcp.input(c, now)
		for _, o := range out {
			if e := l.sendPPP(protoLCP, o); e != nil {
				return e
			}
		}
		if err != nil && l.papRefused && l.ph < phUp {
			return errPAPInClear
		}
		if err != nil {
			return err
		}
		if l.ph == phLCP && l.lcp.open() {
			return l.startAuth(now)
		}
		return nil
	case protoPAP:
		return l.papInput(info)
	case protoCHAP:
		return l.chapInput(info, now)
	case protoIPCP:
		if l.ph < phIPCP {
			return nil // before the login: it's sent again
		}
		c, err := parseCP(info)
		if err != nil {
			return nil
		}
		out, err := l.ipcp.input(c, now)
		for _, o := range out {
			if e := l.sendPPP(protoIPCP, o); e != nil {
				return e
			}
		}
		if err != nil {
			return err
		}
		if l.ph == phIPCP && l.ipcp.open() {
			return l.established()
		}
		return nil
	}
	// Anything else (IPV6CP, CCP, …): refused, so the peer stops asking.
	if l.ph < phLCP || !l.lcp.open() {
		return nil
	}
	l.protoRejID++
	data := binary.BigEndian.AppendUint16(nil, proto)
	data = append(data, info[:min(len(info), 64)]...)
	return l.sendPPP(protoLCP, cp{code: codeProtoRej, id: l.protoRejID, data: data})
}

func tail4(b []byte) []byte {
	if len(b) < 4 {
		return nil
	}
	return b[4:]
}

// lcpPeer decides on the server's LCP options.
func (l *loop) lcpPeer(opts []option) (nak, rej []option) {
	for _, o := range opts {
		switch o.typ {
		case lcpMRU:
			if len(o.data) != 2 {
				rej = append(rej, o)
				continue
			}
			if v := int(binary.BigEndian.Uint16(o.data)); v < 576 {
				nak = append(nak, option{typ: lcpMRU, data: binary.BigEndian.AppendUint16(nil, 576)})
			}
		case lcpACCM, lcpMagic, lcpPFC, lcpACFC:
		case lcpAuth:
			if !l.authOK(o.data) {
				if len(o.data) == 2 && binary.BigEndian.Uint16(o.data) == protoPAP {
					l.papRefused = true
				}
				nak = append(nak, option{typ: lcpAuth, data: []byte{0xc2, 0x23, chapMSCHAPv2}})
			}
		default:
			rej = append(rej, o)
		}
	}
	if len(nak) == 0 && len(rej) == 0 { // acknowledged: these are the link's
		l.auth, l.peerMRU = 0, 0
		for _, o := range opts {
			switch o.typ {
			case lcpMRU:
				l.peerMRU = int(binary.BigEndian.Uint16(o.data))
			case lcpAuth:
				l.auth = binary.BigEndian.Uint16(o.data)
				if l.auth == protoCHAP {
					l.chapAlg = o.data[2]
				}
			}
		}
	}
	return nak, rej
}

// authOK: a login we can do, and may.
func (l *loop) authOK(d []byte) bool {
	if len(d) < 2 {
		return false
	}
	switch binary.BigEndian.Uint16(d) {
	case protoPAP:
		return len(d) == 2 && l.cfg.Encrypted
	case protoCHAP:
		return len(d) == 3 && (d[2] == chapMD5 || d[2] == chapMSCHAPv2)
	}
	return false
}

func (l *loop) lcpNak(opts []option) error {
	for _, o := range opts {
		switch o.typ {
		case lcpMRU:
			if len(o.data) == 2 && binary.BigEndian.Uint16(o.data) >= 576 {
				l.lcp.ours = replace(l.lcp.ours, o)
			} else {
				l.lcp.ours = without(l.lcp.ours, []option{o})
			}
		case lcpMagic:
			_, _ = rand.Read(l.magic)
			l.lcp.ours = replace(l.lcp.ours, option{typ: lcpMagic, data: l.magic})
		}
	}
	return nil
}

func (l *loop) lcpRej(opts []option) error {
	l.lcp.ours = without(l.lcp.ours, opts)
	for _, o := range opts {
		if o.typ == lcpMagic {
			l.magic = []byte{0, 0, 0, 0}
		}
	}
	return nil
}

func (l *loop) ipcpPeer(opts []option) (nak, rej []option) {
	for _, o := range opts {
		if o.typ == ipcpAddress && len(o.data) == 4 {
			continue
		}
		rej = append(rej, o)
	}
	if len(rej) == 0 {
		for _, o := range opts {
			if o.typ == ipcpAddress {
				l.s.peer = netip.AddrFrom4([4]byte(o.data))
			}
		}
	}
	return nil, rej
}

func (l *loop) ipcpNak(opts []option) error {
	for _, o := range opts {
		switch o.typ {
		case ipcpAddress, ipcpDNS1, ipcpDNS2:
			if len(o.data) == 4 {
				l.ipcp.ours = replace(l.ipcp.ours, o)
			}
		}
	}
	return nil
}

func (l *loop) ipcpRej(opts []option) error {
	for _, o := range opts {
		if o.typ == ipcpAddress {
			return errors.New("the server assigned no address: it refuses to give one (IPCP)")
		}
	}
	l.ipcp.ours = without(l.ipcp.ours, opts)
	return nil
}

func (l *loop) established() error {
	for _, o := range l.ipcp.ours {
		a := netip.AddrFrom4([4]byte(o.data))
		switch {
		case o.typ == ipcpAddress:
			if a.IsUnspecified() {
				return errors.New("the server assigned no address (IPCP)")
			}
			l.s.local = a
		case !a.IsUnspecified():
			l.s.dns = append(l.s.dns, a)
		}
	}
	l.s.mtu = l.cfg.MRU
	if l.peerMRU > 0 {
		l.s.mtu = min(l.s.mtu, l.peerMRU)
	}
	l.ph = phUp
	l.lastHeard = time.Now()
	l.log.Info("l2tp session up", "address", l.s.local, "dns", l.s.dns, "mtu", l.s.mtu)
	return nil
}

// --- the login ---

func (l *loop) startAuth(now time.Time) error {
	l.ph = phAuth
	l.authAt = now
	switch l.auth {
	case 0:
		return l.afterAuth(now)
	case protoPAP:
		return l.sendPAP(now)
	}
	return nil // CHAP: the server challenges
}

func (l *loop) afterAuth(now time.Time) error {
	l.authDone = true
	l.ph = phIPCP
	return l.sendPPP(protoIPCP, l.ipcp.request(now))
}

func (l *loop) sendPAP(now time.Time) error {
	if l.papTries >= cpMaxTries {
		return errors.New("the server never answered the login (PAP)")
	}
	l.papTries++
	l.papID++
	l.papNext = now.Add(cpRestart)
	d := []byte{byte(len(l.cfg.Username))}
	d = append(d, l.cfg.Username...)
	d = append(d, byte(len(l.cfg.Password)))
	d = append(d, l.cfg.Password...)
	return l.sendPPP(protoPAP, cp{code: 1, id: l.papID, data: d})
}

func (l *loop) papInput(info []byte) error {
	c, err := parseCP(info)
	if err != nil || l.ph != phAuth || l.auth != protoPAP || c.id != l.papID {
		return nil
	}
	switch c.code {
	case 2: // Authenticate-Ack
		return l.afterAuth(time.Now())
	case 3: // Authenticate-Nak
		return errRejected
	}
	return nil
}

func (l *loop) chapInput(info []byte, now time.Time) error {
	c, err := parseCP(info)
	if err != nil || l.auth != protoCHAP || l.authDone {
		return nil
	}
	switch c.code {
	case 1: // Challenge
		if len(c.data) < 1 || int(c.data[0])+1 > len(c.data) {
			return nil
		}
		value := c.data[1 : 1+int(c.data[0])]
		if c.id != l.chap.id || !bytes.Equal(value, l.chap.challenge) { // a new one
			l.chap.id, l.chap.challenge = c.id, append([]byte{}, value...)
			switch l.chapAlg {
			case chapMD5:
				l.chap.resp = chapMD5Response(c.id, l.cfg.Password, value)
			case chapMSCHAPv2:
				if len(value) != 16 {
					return errors.New("the server's MS-CHAPv2 challenge is malformed")
				}
				l.chap.peer = make([]byte, 16)
				_, _ = rand.Read(l.chap.peer)
				l.chap.resp = mschapv2Response(value, l.chap.peer, l.cfg.Username, l.cfg.Password)
			}
		}
		d := []byte{byte(len(l.chap.resp))}
		d = append(d, l.chap.resp...)
		d = append(d, l.cfg.Username...)
		return l.sendPPP(protoCHAP, cp{code: 2, id: c.id, data: d})
	case 3: // Success
		if c.id != l.chap.id || l.chap.resp == nil {
			return nil
		}
		if l.chapAlg == chapMSCHAPv2 {
			if err := checkMSCHAPv2Success(c.data, l.cfg.Password, l.chap.resp, l.chap.peer, l.chap.challenge, l.cfg.Username); err != nil {
				return err
			}
		}
		return l.afterAuth(now)
	case 4: // Failure
		if c.id != l.chap.id {
			return nil
		}
		if l.chapAlg == chapMSCHAPv2 {
			return msFailure(c.data)
		}
		return errRejected
	}
	return nil
}
