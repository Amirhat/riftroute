//go:build darwin

package tunnel

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

// requireESP gives an L2TP socket policies of its own, both ways: ESP, in
// transport mode, required (the policy libipsec spells "in|out ipsec
// esp/transport//require"). The kernel enforces them whatever happens to
// charon's trap policies: with no SA (charon stopped, its policies gone
// with it) a packet is dropped, never sent in the clear, and a plain one
// from the server isn't taken. macOS matches the SA by its addresses; the
// reqid isn't needed.
func requireESP(fd uintptr, _ uint32) error {
	for _, dir := range []uint8{ipsecDirInbound, ipsecDirOutbound} {
		if err := unix.SetsockoptString(int(fd), unix.IPPROTO_IP, unix.IP_IPSEC_POLICY, string(pfkeyESPPolicy(dir))); err != nil {
			return err
		}
	}
	return nil
}

const (
	ipsecDirInbound    = 1
	ipsecDirOutbound   = 2
	sadbXExtPolicy     = 18
	ipsecPolicyIPsec   = 2
	ipsecModeTransport = 1
	ipsecLevelRequire  = 3
)

// pfkeyESPPolicy is a struct sadb_x_policy (16 bytes) followed by one
// struct sadb_x_ipsecrequest (8): ESP, transport, required.
func pfkeyESPPolicy(dir uint8) []byte {
	b := make([]byte, 24)
	ne := binary.NativeEndian
	ne.PutUint16(b[0:], uint16(len(b)/8)) // sadb_x_policy_len, in 64-bit words
	ne.PutUint16(b[2:], sadbXExtPolicy)
	ne.PutUint16(b[4:], ipsecPolicyIPsec)
	b[6] = dir
	r := b[16:]
	ne.PutUint16(r[0:], 8) // sadb_x_ipsecrequest_len, in bytes
	ne.PutUint16(r[2:], unix.IPPROTO_ESP)
	r[4] = ipsecModeTransport
	r[5] = ipsecLevelRequire
	return b
}
