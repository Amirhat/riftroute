//go:build !windows

package main

import "golang.org/x/sys/unix"

// diskFree reports the free bytes on the volume holding path.
func diskFree(path string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
