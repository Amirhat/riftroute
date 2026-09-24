//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/user"
	"syscall"
)

// requireDataOwner refuses to write into the data directory as anyone but its
// owner: a password file (or database journal) created by root would be
// unreadable to the service, and login would silently stop working.
func requireDataOwner(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("data directory: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) == os.Geteuid() {
		return nil
	}
	owner := fmt.Sprint(st.Uid)
	if u, err := user.LookupId(owner); err == nil {
		owner = u.Username
	}
	return fmt.Errorf("%s belongs to %s; run this as that account: sudo -u %s riftroute-server passwd -data %s", dir, owner, owner, dir)
}
