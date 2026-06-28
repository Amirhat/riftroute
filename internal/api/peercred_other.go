//go:build !darwin && !linux

package api

import "errors"

// peerCred is unsupported on platforms without SO_PEERCRED/LOCAL_PEERCRED. The
// daemon ships only as a stub on such platforms (spec §8 always-compiles), so
// this keeps the project building while failing closed for authz.
func peerCred(fd uintptr) (uint32, uint32, error) {
	return 0, 0, errors.New("peer credentials unsupported on this platform")
}
