//go:build !darwin && !linux

package tunnel

// wgSystem: WireGuard tunnels run on macOS and Linux only.
func wgSystem() WGSystem { return nil }

// l2tpSystem is the same for L2TP tunnels.
func l2tpSystem() WGSystem { return wgSystem() }
