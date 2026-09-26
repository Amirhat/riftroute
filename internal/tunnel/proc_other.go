//go:build !linux && !windows

package tunnel

import "syscall"

// parentDeath: only Linux can tie a child's life to its parent's; elsewhere
// management-signal and the next start's reaping cover a daemon that died.
func parentDeath(*syscall.SysProcAttr) {}
