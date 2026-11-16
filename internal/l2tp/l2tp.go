// Package l2tp is an L2TP client (an LAC, RFC 2661) with PPP inside it: the
// control connection, one session, and PPP's LCP, login and IPCP, carrying
// IPv4 packets. IPsec, which encrypts it, is strongSwan's (see
// docs/tunnels-l2tp.md); this package sees only the UDP socket.
package l2tp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Header flag bits (RFC 2661 §3.1).
const (
	flagT   = 0x8000 // control message
	flagL   = 0x4000 // length present
	flagS   = 0x0800 // Ns and Nr present
	flagO   = 0x0200 // offset size present
	flagP   = 0x0100 // priority
	verMask = 0x000f
	version = 2
)

// Control message types (the Message Type AVP's value).
const (
	msgSCCRQ   = 1
	msgSCCRP   = 2
	msgSCCCN   = 3
	msgStopCCN = 4
	msgHello   = 6
	msgICRQ    = 10
	msgICRP    = 11
	msgICCN    = 12
	msgCDN     = 14
	msgWEN     = 15
	msgSLI     = 16
)

var msgNames = map[uint16]string{
	msgSCCRQ: "SCCRQ", msgSCCRP: "SCCRP", msgSCCCN: "SCCCN", msgStopCCN: "StopCCN",
	msgHello: "HELLO", msgICRQ: "ICRQ", msgICRP: "ICRP", msgICCN: "ICCN", msgCDN: "CDN",
	msgWEN: "WEN", msgSLI: "SLI",
}

func msgName(t uint16) string {
	if n, ok := msgNames[t]; ok {
		return n
	}
	return fmt.Sprintf("message %d", t)
}

// AVP attribute types (RFC 2661 §4.4).
const (
	avpMessageType      = 0
	avpResultCode       = 1
	avpProtocolVersion  = 2
	avpFramingCaps      = 3
	avpBearerCaps       = 4
	avpFirmwareRevision = 6
	avpHostName         = 7
	avpVendorName       = 8
	avpAssignedTunnelID = 9
	avpReceiveWindow    = 10
	avpChallenge        = 11
	avpAssignedSession  = 14
	avpCallSerial       = 15
	avpFramingType      = 19
	avpTxConnectSpeed   = 24
)

// avp is one attribute-value pair.
type avp struct {
	mandatory bool
	hidden    bool
	vendor    uint16
	typ       uint16
	value     []byte
}

func (a avp) u16() (uint16, error) {
	if len(a.value) != 2 {
		return 0, fmt.Errorf("AVP %d: %d bytes, want 2", a.typ, len(a.value))
	}
	return binary.BigEndian.Uint16(a.value), nil
}

func u16AVP(typ, v uint16) avp {
	return avp{mandatory: true, typ: typ, value: binary.BigEndian.AppendUint16(nil, v)}
}

func u32AVP(typ uint16, v uint32) avp {
	return avp{mandatory: true, typ: typ, value: binary.BigEndian.AppendUint32(nil, v)}
}

// message is a parsed L2TP packet.
type message struct {
	control   bool
	tunnel    uint16
	session   uint16
	ns, nr    uint16
	sequenced bool
	avps      []avp  // control
	payload   []byte // data
}

// msgType is a control message's type; a ZLB (no AVPs) is 0.
func (m *message) msgType() uint16 {
	if len(m.avps) == 0 {
		return 0
	}
	v, _ := m.avps[0].u16()
	return v
}

func (m *message) find(typ uint16) (avp, bool) {
	for _, a := range m.avps {
		if a.vendor == 0 && a.typ == typ {
			return a, true
		}
	}
	return avp{}, false
}

var errShort = errors.New("l2tp: packet too short")

// parse reads one L2TP packet.
func parse(b []byte) (*message, error) {
	if len(b) < 6 {
		return nil, errShort
	}
	flags := binary.BigEndian.Uint16(b)
	if flags&verMask != version {
		return nil, fmt.Errorf("l2tp: version %d", flags&verMask)
	}
	m := &message{control: flags&flagT != 0}
	off := 2
	end := len(b)
	if flags&flagL != 0 {
		if len(b) < off+2 {
			return nil, errShort
		}
		n := int(binary.BigEndian.Uint16(b[off:]))
		if n < 6 || n > len(b) {
			return nil, fmt.Errorf("l2tp: length %d of a %d-byte packet", n, len(b))
		}
		end = n
		off += 2
	}
	if end < off+4 {
		return nil, errShort
	}
	m.tunnel = binary.BigEndian.Uint16(b[off:])
	m.session = binary.BigEndian.Uint16(b[off+2:])
	off += 4
	if flags&flagS != 0 {
		if end < off+4 {
			return nil, errShort
		}
		m.sequenced = true
		m.ns = binary.BigEndian.Uint16(b[off:])
		m.nr = binary.BigEndian.Uint16(b[off+2:])
		off += 4
	}
	if flags&flagO != 0 {
		if end < off+2 {
			return nil, errShort
		}
		pad := int(binary.BigEndian.Uint16(b[off:]))
		off += 2 + pad
		if off > end {
			return nil, errShort
		}
	}
	if !m.control {
		m.payload = b[off:end]
		return m, nil
	}
	if flags&(flagL|flagS) != flagL|flagS {
		return nil, errors.New("l2tp: a control message without length or sequence numbers")
	}
	for off < end {
		if end-off < 6 {
			return nil, errShort
		}
		h := binary.BigEndian.Uint16(b[off:])
		n := int(h & 0x03ff)
		if n < 6 || off+n > end {
			return nil, fmt.Errorf("l2tp: AVP length %d", n)
		}
		m.avps = append(m.avps, avp{
			mandatory: h&0x8000 != 0,
			hidden:    h&0x4000 != 0,
			vendor:    binary.BigEndian.Uint16(b[off+2:]),
			typ:       binary.BigEndian.Uint16(b[off+4:]),
			value:     b[off+6 : off+n],
		})
		off += n
	}
	if len(m.avps) > 0 {
		if a := m.avps[0]; a.vendor != 0 || a.typ != avpMessageType || a.hidden || len(a.value) != 2 {
			return nil, errors.New("l2tp: a control message whose first AVP isn't its type")
		}
	}
	return m, nil
}

// controlPacket encodes a control message (a ZLB when avps is empty).
func controlPacket(tunnel, session, ns, nr uint16, avps []avp) []byte {
	b := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(b, flagT|flagL|flagS|version)
	binary.BigEndian.PutUint16(b[4:], tunnel)
	binary.BigEndian.PutUint16(b[6:], session)
	binary.BigEndian.PutUint16(b[8:], ns)
	binary.BigEndian.PutUint16(b[10:], nr)
	for _, a := range avps {
		h := uint16(6 + len(a.value))
		if a.mandatory {
			h |= 0x8000
		}
		b = binary.BigEndian.AppendUint16(b, h)
		b = binary.BigEndian.AppendUint16(b, a.vendor)
		b = binary.BigEndian.AppendUint16(b, a.typ)
		b = append(b, a.value...)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

// dataHeaderLen is the data header we send: flags, tunnel, session.
const dataHeaderLen = 6

// putDataHeader writes a data message's header into b[:dataHeaderLen].
func putDataHeader(b []byte, tunnel, session uint16) {
	binary.BigEndian.PutUint16(b, version)
	binary.BigEndian.PutUint16(b[2:], tunnel)
	binary.BigEndian.PutUint16(b[4:], session)
}

// resultCode reads a Result Code AVP: the code, the error code, the message.
func resultCode(m *message) (code, errCode uint16, text string) {
	a, ok := m.find(avpResultCode)
	if !ok || len(a.value) < 2 {
		return 0, 0, ""
	}
	code = binary.BigEndian.Uint16(a.value)
	if len(a.value) >= 4 {
		errCode = binary.BigEndian.Uint16(a.value[2:])
	}
	if len(a.value) > 4 {
		text = printable(a.value[4:])
	}
	return
}

// printable keeps a server's text to what's safe to log and show.
func printable(b []byte) string {
	out := make([]rune, 0, len(b))
	for _, r := range string(b) {
		if r >= 0x20 && r != 0x7f && r != 0xfffd {
			out = append(out, r)
		}
		if len(out) >= 200 {
			break
		}
	}
	return string(out)
}

// seqLess reports whether a comes before b, modulo 2^16 (RFC 2661 §5.8).
func seqLess(a, b uint16) bool { return int16(a-b) < 0 }
