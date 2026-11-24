//go:build linux

package tunnel

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

// requireESP gives an L2TP socket policies of its own, both ways: ESP, in
// transport mode, required, for the CHILD_SA charon installed (reqid). The
// kernel enforces them whatever happens to charon's trap policies: with no
// SA (charon stopped, its policies gone with it) a packet is dropped, never
// sent in the clear, and a plain one from the server isn't taken.
func requireESP(fd uintptr, reqid uint32) error {
	for _, dir := range []uint8{xfrmPolicyIn, xfrmPolicyOut} {
		if err := unix.SetsockoptString(int(fd), unix.SOL_IP, unix.IP_XFRM_POLICY, string(xfrmESPPolicy(dir, reqid))); err != nil {
			return err
		}
	}
	return nil
}

const (
	xfrmPolicyIn  = 0
	xfrmPolicyOut = 1
	xfrmInf       = ^uint64(0)
)

// xfrmESPPolicy is a struct xfrm_userpolicy_info (168 bytes on the 64-bit
// targets RiftRoute builds) followed by one struct xfrm_user_tmpl (64):
// the selector is the socket's own; the template is ESP, transport mode,
// not optional, this reqid, any algorithm.
func xfrmESPPolicy(dir uint8, reqid uint32) []byte {
	b := make([]byte, 168+64)
	ne := binary.NativeEndian
	ne.PutUint16(b[40:], unix.AF_INET) // sel.family
	for i := range 4 {                 // lft: no byte or packet limits
		ne.PutUint64(b[56+8*i:], xfrmInf)
	}
	b[160] = dir // dir; action (161) 0: allow, through the template
	t := b[168:]
	t[20] = unix.IPPROTO_ESP           // id.proto (daddr, spi: any)
	ne.PutUint16(t[24:], unix.AF_INET) // family
	ne.PutUint32(t[44:], reqid)        // reqid
	// mode (48) 0: transport; share (49) 0: any; optional (50) 0: required.
	ne.PutUint32(t[52:], ^uint32(0)) // aalgos
	ne.PutUint32(t[56:], ^uint32(0)) // ealgos
	ne.PutUint32(t[60:], ^uint32(0)) // calgos
	return b
}
