//go:build !darwin && !linux

package tunnel

// wgSystem: WireGuard tunnels run on macOS and Linux only.
func wgSystem() WGSystem { return nil }
