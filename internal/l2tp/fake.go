package l2tp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
)

// FakeServer is a minimal L2TP server (an LNS) with PPP, for tests and the
// daemon's -provider fake: it answers one client at a time, logs it in
// against Users, assigns Address and DNS, and hands the client's IPv4
// packets to Received. It doesn't retransmit (it runs on loopback).
type FakeServer struct {
	Users   map[string]string // username → password
	Auth    string            // "mschapv2" (default), "chap", "pap", "none"
	Address netip.Addr        // assigned (default 10.77.0.2); the server's is 10.77.0.1
	DNS     []netip.Addr
	MRU     int // asked for in LCP (default 1400)
	// Faults.
	Silent           bool // answers nothing
	TunnelSecret     bool // asks for a tunnel secret (a Challenge AVP)
	BadAuthenticator bool // MS-CHAPv2 success that doesn't prove the password
	NoAddress        bool // rejects the client's address option
	Insist           bool // ends the session when its login is refused
	// AnyPassword (-provider fake): PAP takes any password but "wrong"; a
	// client that won't send it in the clear (no IPsec) is let in unasked.
	AnyPassword bool

	mu       sync.Mutex
	conn     *net.UDPConn
	client   *net.UDPAddr
	received chan []byte
	logins   int
	st       fakeState
}

type fakeState struct {
	ourTunnel, peerTunnel uint16
	ourSess, peerSess     uint16
	ns, nr                uint16
	lcpAckedOurs          bool
	lcpAckedTheirs        bool
	authed                bool
	challenge             []byte
	chapID                uint8
	ipcpUp                bool
}

// Start listens on 127.0.0.1 and returns the address.
func (f *FakeServer) Start() (netip.AddrPort, error) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return netip.AddrPort{}, err
	}
	f.mu.Lock()
	f.conn = c
	f.received = make(chan []byte, 64)
	if !f.Address.IsValid() {
		f.Address = netip.MustParseAddr("10.77.0.2")
	}
	if f.MRU == 0 {
		f.MRU = 1400
	}
	if f.Auth == "" {
		f.Auth = "mschapv2"
	}
	f.mu.Unlock()
	go f.serve()
	return c.LocalAddr().(*net.UDPAddr).AddrPort(), nil
}

// Close stops it.
func (f *FakeServer) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conn != nil {
		_ = f.conn.Close()
	}
}

// Received are the client's IPv4 packets.
func (f *FakeServer) Received() <-chan []byte { return f.received }

// Logins counts the login attempts it judged.
func (f *FakeServer) Logins() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logins
}

// Send sends an IPv4 packet to the client.
func (f *FakeServer) Send(pkt []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ppp(protoIPv4, pkt)
}

// HangUp closes the tunnel (StopCCN), as a server going away does.
func (f *FakeServer) HangUp() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ctl(0, []avp{u16AVP(avpMessageType, msgStopCCN), u16AVP(avpAssignedTunnelID, f.st.ourTunnel),
		{mandatory: true, typ: avpResultCode, value: append([]byte{0, 6, 0, 0}, "going away"...)}})
}

func (f *FakeServer) serve() {
	buf := make([]byte, 2048)
	for {
		n, from, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		f.mu.Lock()
		if !f.Silent {
			f.input(append([]byte{}, buf[:n]...), from)
		}
		f.mu.Unlock()
	}
}

func (f *FakeServer) write(b []byte) error {
	if f.client == nil {
		return nil
	}
	_, err := f.conn.WriteToUDP(b, f.client)
	return err
}

func (f *FakeServer) ctl(session uint16, avps []avp) {
	_ = f.write(controlPacket(f.st.peerTunnel, session, f.st.ns, f.st.nr, avps))
	f.st.ns++
}

func (f *FakeServer) ppp(proto uint16, info []byte) error {
	b := make([]byte, dataHeaderLen+pppHeaderLen)
	putDataHeader(b, f.st.peerTunnel, f.st.peerSess)
	putPPPHeader(b[dataHeaderLen:], proto)
	return f.write(append(b, info...))
}

func (f *FakeServer) input(b []byte, from *net.UDPAddr) {
	m, err := parse(b)
	if err != nil {
		return
	}
	if !m.control {
		f.pppInput(m.payload)
		return
	}
	if len(m.avps) == 0 {
		return
	}
	if m.msgType() == msgSCCRQ && m.tunnel == 0 && m.ns == 0 {
		f.st = fakeState{} // a new tunnel: start over
	}
	if m.ns != f.st.nr { // a duplicate: acknowledge it again
		_ = f.write(controlPacket(f.st.peerTunnel, 0, f.st.ns, f.st.nr, nil))
		return
	}
	f.st.nr++
	switch m.msgType() {
	case msgSCCRQ:
		a, _ := m.find(avpAssignedTunnelID)
		id, _ := a.u16()
		f.client = from
		f.st = fakeState{ourTunnel: nonzero16(), peerTunnel: id, nr: 1}
		avps := []avp{u16AVP(avpMessageType, msgSCCRP), u16AVP(avpProtocolVersion, 0x0100),
			{mandatory: true, typ: avpHostName, value: []byte("fake-lns")}, u32AVP(avpFramingCaps, 3),
			u16AVP(avpAssignedTunnelID, f.st.ourTunnel)}
		if f.TunnelSecret {
			avps = append(avps, avp{mandatory: true, typ: avpChallenge, value: []byte("0123456789abcdef")})
		}
		f.ctl(0, avps)
	case msgICRQ:
		a, _ := m.find(avpAssignedSession)
		f.st.peerSess, _ = a.u16()
		f.st.ourSess = nonzero16()
		f.ctl(f.st.peerSess, []avp{u16AVP(avpMessageType, msgICRP), u16AVP(avpAssignedSession, f.st.ourSess)})
	case msgICCN:
		_ = f.write(controlPacket(f.st.peerTunnel, 0, f.st.ns, f.st.nr, nil))
		opts := []option{{typ: lcpMRU, data: binary.BigEndian.AppendUint16(nil, uint16(f.MRU))}, {typ: lcpMagic, data: []byte{1, 2, 3, 4}}}
		switch f.Auth {
		case "mschapv2":
			opts = append(opts, option{typ: lcpAuth, data: []byte{0xc2, 0x23, chapMSCHAPv2}})
		case "chap":
			opts = append(opts, option{typ: lcpAuth, data: []byte{0xc2, 0x23, chapMD5}})
		case "pap":
			opts = append(opts, option{typ: lcpAuth, data: []byte{0xc0, 0x23}})
		}
		_ = f.ppp(protoLCP, cp{code: codeConfReq, id: 1, data: encodeOptions(opts)}.bytes())
	default: // SCCCN, HELLO, CDN, StopCCN: acknowledged
		_ = f.write(controlPacket(f.st.peerTunnel, 0, f.st.ns, f.st.nr, nil))
	}
}

func (f *FakeServer) pppInput(frame []byte) {
	proto, info, err := pppFrame(frame)
	if err != nil {
		return
	}
	if proto == protoIPv4 {
		select {
		case f.received <- append([]byte{}, info...):
		default:
		}
		return
	}
	c, err := parseCP(info)
	if err != nil {
		return
	}
	switch proto {
	case protoLCP:
		switch c.code {
		case codeConfReq:
			_ = f.ppp(protoLCP, cp{code: codeConfAck, id: c.id, data: c.data}.bytes())
			f.st.lcpAckedTheirs = true
		case codeConfAck:
			f.st.lcpAckedOurs = true
		case codeConfNak: // it wants another login: give in once
			if f.Insist {
				_ = f.ppp(protoLCP, cp{code: codeTermReq, id: 9}.bytes())
				return
			}
			if f.AnyPassword {
				f.Auth = "none"
				_ = f.ppp(protoLCP, cp{code: codeConfReq, id: c.id + 1, data: encodeOptions([]option{
					{typ: lcpMRU, data: binary.BigEndian.AppendUint16(nil, uint16(f.MRU))}})}.bytes())
				return
			}
			opts, _ := parseOptions(c.data)
			for _, o := range opts {
				if o.typ == lcpAuth && len(o.data) == 3 && o.data[2] == chapMSCHAPv2 {
					f.Auth = "mschapv2"
				}
			}
			_ = f.ppp(protoLCP, cp{code: codeConfReq, id: c.id + 1, data: encodeOptions([]option{
				{typ: lcpMRU, data: binary.BigEndian.AppendUint16(nil, uint16(f.MRU))}, {typ: lcpAuth, data: []byte{0xc2, 0x23, chapMSCHAPv2}}})}.bytes())
		}
		if f.st.lcpAckedOurs && f.st.lcpAckedTheirs && !f.st.authed && f.st.challenge == nil {
			f.startAuth()
		}
	case protoCHAP:
		if c.code != 2 || c.id != f.st.chapID || len(c.data) < 1 {
			return
		}
		n := int(c.data[0])
		if 1+n > len(c.data) {
			return
		}
		value, name := c.data[1:1+n], string(c.data[1+n:])
		f.logins++
		pass, known := f.Users[name]
		switch f.Auth {
		case "chap":
			if known && subtle.ConstantTimeCompare(value, chapMD5Response(c.id, pass, f.st.challenge)) == 1 {
				f.authOK(protoCHAP, cp{code: 3, id: c.id, data: []byte("welcome")})
				return
			}
			_ = f.ppp(protoCHAP, cp{code: 4, id: c.id, data: []byte("no")}.bytes())
		default:
			if n != 49 {
				return
			}
			peer, nt := value[:16], value[24:48]
			if known && subtle.ConstantTimeCompare(nt, ntResponse(f.st.challenge, peer, name, pass)) == 1 {
				s := authenticatorResponse(pass, nt, peer, f.st.challenge, name)
				if f.BadAuthenticator {
					s = "S=0000000000000000000000000000000000000000"
				}
				f.authOK(protoCHAP, cp{code: 3, id: c.id, data: []byte(s + " M=welcome")})
				return
			}
			_ = f.ppp(protoCHAP, cp{code: 4, id: c.id, data: []byte("E=691 R=0 C=00 V=3 M=bad login")}.bytes())
		}
	case protoPAP:
		if c.code != 1 || len(c.data) < 1 {
			return
		}
		ul := int(c.data[0])
		if 1+ul+1 > len(c.data) {
			return
		}
		user := string(c.data[1 : 1+ul])
		pl := int(c.data[1+ul])
		if 2+ul+pl > len(c.data) {
			return
		}
		f.logins++
		given := string(c.data[2+ul : 2+ul+pl])
		if pass, ok := f.Users[user]; (ok && pass == given) || (f.AnyPassword && given != "wrong") {
			f.authOK(protoPAP, cp{code: 2, id: c.id})
			return
		}
		_ = f.ppp(protoPAP, cp{code: 3, id: c.id}.bytes())
	case protoIPCP:
		f.ipcp(c)
	}
}

func (f *FakeServer) startAuth() {
	switch f.Auth {
	case "none":
		f.authOK(0, cp{})
	case "pap": // the client sends first
	default:
		f.st.challenge = make([]byte, 16)
		_, _ = rand.Read(f.st.challenge)
		f.st.chapID++
		d := append([]byte{16}, f.st.challenge...)
		_ = f.ppp(protoCHAP, cp{code: 1, id: f.st.chapID, data: append(d, "fake-lns"...)}.bytes())
	}
}

func (f *FakeServer) authOK(proto uint16, ok cp) {
	if proto != 0 {
		_ = f.ppp(proto, ok.bytes())
	}
	f.st.authed = true
	server := netip.MustParseAddr("10.77.0.1").As4()
	_ = f.ppp(protoIPCP, cp{code: codeConfReq, id: 1, data: encodeOptions([]option{{typ: ipcpAddress, data: server[:]}})}.bytes())
}

func (f *FakeServer) ipcp(c cp) {
	if c.code != codeConfReq {
		return
	}
	opts, err := parseOptions(c.data)
	if err != nil {
		return
	}
	want := map[uint8][]byte{ipcpAddress: f.Address.AsSlice()}
	for i, k := range []uint8{ipcpDNS1, ipcpDNS2} {
		if i < len(f.DNS) {
			want[k] = f.DNS[i].AsSlice()
		}
	}
	var nak, rej []option
	for _, o := range opts {
		w, ok := want[o.typ]
		switch {
		case !ok || (o.typ == ipcpAddress && f.NoAddress):
			rej = append(rej, o)
		case string(w) != string(o.data):
			nak = append(nak, option{typ: o.typ, data: w})
		}
	}
	switch {
	case len(rej) > 0:
		_ = f.ppp(protoIPCP, cp{code: codeConfRej, id: c.id, data: encodeOptions(rej)}.bytes())
	case len(nak) > 0:
		_ = f.ppp(protoIPCP, cp{code: codeConfNak, id: c.id, data: encodeOptions(nak)}.bytes())
	default:
		_ = f.ppp(protoIPCP, cp{code: codeConfAck, id: c.id, data: c.data}.bytes())
		f.st.ipcpUp = true
	}
}
