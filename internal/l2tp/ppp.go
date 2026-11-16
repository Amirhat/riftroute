package l2tp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// PPP protocol numbers.
const (
	protoIPv4   = 0x0021
	protoIPv6   = 0x0057
	protoLCP    = 0xc021
	protoPAP    = 0xc023
	protoCHAP   = 0xc223
	protoIPCP   = 0x8021
	protoIPV6CP = 0x8057
	protoCCP    = 0x80fd
)

// Control protocol codes (RFC 1661 §5).
const (
	codeConfReq   = 1
	codeConfAck   = 2
	codeConfNak   = 3
	codeConfRej   = 4
	codeTermReq   = 5
	codeTermAck   = 6
	codeCodeRej   = 7
	codeProtoRej  = 8
	codeEchoReq   = 9
	codeEchoReply = 10
	codeDiscard   = 11
)

// LCP options.
const (
	lcpMRU   = 1
	lcpACCM  = 2
	lcpAuth  = 3
	lcpMagic = 5
	lcpPFC   = 7
	lcpACFC  = 8
)

// IPCP options (RFC 1332, RFC 1877).
const (
	ipcpAddress = 3
	ipcpDNS1    = 129
	ipcpDNS2    = 131
)

// CHAP algorithms.
const (
	chapMD5      = 0x05
	chapMSCHAPv2 = 0x81
)

// pppFrame splits a PPP frame (an L2TP data payload): its protocol and
// information. The address and control bytes, and a compressed protocol
// field, are accepted either way.
func pppFrame(b []byte) (proto uint16, info []byte, err error) {
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0x03 {
		b = b[2:]
	}
	if len(b) < 1 {
		return 0, nil, errShort
	}
	if b[0]&1 == 1 { // compressed (one byte)
		return uint16(b[0]), b[1:], nil
	}
	if len(b) < 2 {
		return 0, nil, errShort
	}
	return binary.BigEndian.Uint16(b), b[2:], nil
}

// pppHeaderLen is what we put before a PPP frame's information: address,
// control, protocol (never compressed: a peer must accept that).
const pppHeaderLen = 4

func putPPPHeader(b []byte, proto uint16) {
	b[0], b[1] = 0xff, 0x03
	binary.BigEndian.PutUint16(b[2:], proto)
}

// cp is a control protocol packet (LCP, IPCP, PAP, CHAP).
type cp struct {
	code, id uint8
	data     []byte
}

func parseCP(b []byte) (cp, error) {
	if len(b) < 4 {
		return cp{}, errShort
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	if n < 4 || n > len(b) {
		return cp{}, fmt.Errorf("ppp: length %d of %d bytes", n, len(b))
	}
	return cp{code: b[0], id: b[1], data: b[4:n]}, nil
}

func (c cp) bytes() []byte {
	b := make([]byte, 4, 4+len(c.data))
	b[0], b[1] = c.code, c.id
	binary.BigEndian.PutUint16(b[2:], uint16(4+len(c.data)))
	return append(b, c.data...)
}

// option is a configuration option.
type option struct {
	typ  uint8
	data []byte
}

func parseOptions(b []byte) ([]option, error) {
	var opts []option
	for len(b) > 0 {
		if len(b) < 2 || b[1] < 2 || int(b[1]) > len(b) {
			return nil, errors.New("ppp: malformed options")
		}
		opts = append(opts, option{typ: b[0], data: b[2:b[1]]})
		b = b[b[1]:]
	}
	return opts, nil
}

func encodeOptions(opts []option) []byte {
	var b []byte
	for _, o := range opts {
		b = append(b, o.typ, uint8(2+len(o.data)))
		b = append(b, o.data...)
	}
	return b
}

// ncp negotiates one control protocol's options (LCP, IPCP): our
// Configure-Request until it's acknowledged, and an answer to each of the
// peer's. It's open once both sides have acknowledged the other's.
type ncp struct {
	proto uint16
	name  string
	ours  []option // our current request
	id    uint8    // our last request's
	// peer decides on the peer's request: what to acknowledge, nak (with
	// the values we want instead) and reject.
	peer func(opts []option) (nak, rej []option)
	// nak and rej adjust ours after the peer's Nak or Reject; an error
	// ends the session.
	nak func(opts []option) error
	rej func(opts []option) error

	ackedOurs, ackedTheirs bool
	tries                  int
	next                   time.Time
	naks                   int // in a row, to stop a loop
}

const (
	cpRestart  = 3 * time.Second
	cpMaxTries = 10
	cpMaxNaks  = 5
)

func (n *ncp) open() bool { return n.ackedOurs && n.ackedTheirs }

// request is our next Configure-Request.
func (n *ncp) request(now time.Time) cp {
	n.id++
	n.tries++
	n.next = now.Add(cpRestart)
	return cp{code: codeConfReq, id: n.id, data: encodeOptions(n.ours)}
}

// due reports whether our request should be sent again, and an error when
// the peer never answered.
func (n *ncp) due(now time.Time) (bool, error) {
	if n.ackedOurs || now.Before(n.next) {
		return false, nil
	}
	if n.tries >= cpMaxTries {
		return false, fmt.Errorf("the server didn't answer %s (%d requests)", n.name, n.tries)
	}
	return true, nil
}

// input handles one of the protocol's packets; it returns the packets to
// send.
func (n *ncp) input(c cp, now time.Time) (out []cp, err error) {
	switch c.code {
	case codeConfReq:
		opts, err := parseOptions(c.data)
		if err != nil {
			return nil, err
		}
		if n.open() { // the peer starts over: so do we
			n.ackedOurs, n.tries = false, 0
			out = append(out, n.request(now))
		}
		nak, rej := n.peer(opts)
		switch {
		case len(rej) > 0:
			n.ackedTheirs = false
			out = append(out, cp{code: codeConfRej, id: c.id, data: encodeOptions(rej)})
		case len(nak) > 0:
			n.ackedTheirs = false
			out = append(out, cp{code: codeConfNak, id: c.id, data: encodeOptions(nak)})
		default:
			n.ackedTheirs = true
			out = append(out, cp{code: codeConfAck, id: c.id, data: c.data})
		}
	case codeConfAck:
		if c.id == n.id && !n.ackedOurs {
			n.ackedOurs, n.naks = true, 0
		}
	case codeConfNak, codeConfRej:
		if c.id != n.id || n.ackedOurs {
			return nil, nil
		}
		opts, err := parseOptions(c.data)
		if err != nil {
			return nil, err
		}
		if n.naks++; n.naks > cpMaxNaks {
			return nil, fmt.Errorf("%s: the server and RiftRoute couldn't agree on its options", n.name)
		}
		if c.code == codeConfNak {
			err = n.nak(opts)
		} else {
			err = n.rej(opts)
		}
		if err != nil {
			return nil, err
		}
		n.tries = 0
		out = append(out, n.request(now))
	case codeTermReq:
		return []cp{{code: codeTermAck, id: c.id}}, errTerminated
	case codeTermAck, codeCodeRej, codeEchoReply, codeDiscard:
	default:
		out = append(out, cp{code: codeCodeRej, id: c.id, data: c.bytes()})
	}
	return out, nil
}

// errTerminated: the peer sent a Terminate-Request.
var errTerminated = errors.New("the server ended the PPP session")

// without returns opts without the options of the given types.
func without(opts []option, drop []option) []option {
	var out []option
	for _, o := range opts {
		gone := false
		for _, d := range drop {
			if d.typ == o.typ {
				gone = true
				break
			}
		}
		if !gone {
			out = append(out, o)
		}
	}
	return out
}

// replace sets an option's value in opts.
func replace(opts []option, o option) []option {
	for i := range opts {
		if opts[i].typ == o.typ {
			opts[i].data = o.data
			return opts
		}
	}
	return append(opts, o)
}
