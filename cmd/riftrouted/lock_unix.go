//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// lockInstance takes an exclusive lock beside the database, held until the
// process exits. A second daemon on the same state — a manual run beside the
// service — stops here, before it touches anything: the boot guard's start
// count, the routes, or the running daemon's tunnels (whose openvpn it would
// otherwise reap as "left by a crashed daemon").
func lockInstance(dir string) error {
	p := filepath.Join(dir, "riftrouted.lock")
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("instance lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("another riftrouted is already running with %s; stop it first", dir)
		}
		return fmt.Errorf("instance lock: %w", err)
	}
	instanceLock = f // held (open) for the life of the process
	return nil
}

var instanceLock *os.File
