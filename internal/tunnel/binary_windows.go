package tunnel

import (
	"errors"
	"io/fs"
)

// Tunnels don't run on Windows; nothing is ever found safe to run here.
func lstatOwner(string) (fs.FileInfo, uint32, error) {
	return nil, 0, errors.New("tunnels aren't supported on windows")
}

func fileIno(fs.FileInfo) uint64 { return 0 }
