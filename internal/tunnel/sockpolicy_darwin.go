//go:build darwin

package tunnel

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

// requireESP gives an L2TP socket an outbound policy of its own: ESP, in
// transport mode, required (libipsec's "out ipsec esp/transport//require").
// The kernel enforces it whatever happens to charon's trap policies: with
// no SA (charon stopped, its policies gone with it) a packet is dropped,
// never sent in the clear. macOS matches the SA by its addresses; the
// reqid isn't needed.
//
// shortcut: outbound only on macOS. Both ways cut the owner's live test
// (2026-11-24: SA up, no L2TP reply), most likely the inbound check on
// NAT-T-decapsulated packets; charon's own policy still covers inbound.
// Revisit with a test that shows which way failed.
func requireESP(fd uintptr, _ uint32) error {
	for _, dir := range []uint8{ipsecDirOutbound} {
		if err := unix.SetsockoptString(int(fd), unix.IPPROTO_IP, unix.IP_IPSEC_POLICY, string(pfkeyESPPolicy(dir))); err != nil {
			return err
		}
	}
	return nil
}

const (
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
