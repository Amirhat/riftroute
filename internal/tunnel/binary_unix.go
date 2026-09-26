//go:build !windows

package tunnel

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// lstatOwner is os.Lstat plus the owner's uid, which the check needs: a
// file whose owner can't be read is never taken to be root's.
func lstatOwner(path string) (fs.FileInfo, uint32, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, 0, fmt.Errorf("%s: can't read its owner", path)
	}
	return fi, st.Uid, nil
}

// fileIno is a file's inode number (0 when unknown): part of what identifies
// a binary, so one replaced in place is noticed.
func fileIno(fi fs.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}
