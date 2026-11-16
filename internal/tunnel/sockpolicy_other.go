//go:build !linux && !darwin

package tunnel

import "errors"

// requireESP: L2TP/IPsec runs on macOS and Linux only.
func requireESP(uintptr, uint32) error {
	return errors.New("L2TP/IPsec tunnels run on macOS and Linux")
}
