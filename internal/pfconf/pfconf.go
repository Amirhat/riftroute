// Package pfconf coordinates edits of the macOS packet-filter config
// (/etc/pf.conf), which two parts of RiftRoute each hook an anchor into:
// policy routing (internal/provider/macos) and the kill switch
// (internal/killswitch). Both read-modify-write the same file; Mu keeps one
// from silently dropping the other's hook.
package pfconf

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Path is the packet-filter config both hooks live in.
const Path = "/etc/pf.conf"

// Mu serializes every read-modify-write of pf.conf within the daemon.
var Mu sync.Mutex

// Block renders a marked, reversible block referencing one anchor.
func Block(begin, end, anchor string) string {
	return begin + "\n" + `anchor "` + anchor + `"` + "\n" + end + "\n"
}

// Has reports whether conf already contains the marked block.
func Has(conf, begin string) bool { return strings.Contains(conf, begin) }

// Insert appends the block (idempotent), after everything else so the
// system's own rules keep their order.
func Insert(conf, begin, end, anchor string) string {
	if Has(conf, begin) {
		return conf
	}
	if conf != "" && !strings.HasSuffix(conf, "\n") {
		conf += "\n"
	}
	return conf + Block(begin, end, anchor)
}

// Remove strips the marked block (idempotent), leaving the rest byte-identical.
func Remove(conf, begin, end string) string {
	i := strings.Index(conf, begin)
	if i < 0 {
		return conf
	}
	j := strings.Index(conf[i:], end)
	if j < 0 {
		return conf // malformed: leave it for a human rather than guess
	}
	k := i + j + len(end)
	if k < len(conf) && conf[k] == '\n' {
		k++
	}
	return conf[:i] + conf[k:]
}

// WriteAtomic replaces path via a same-directory temp file + fsync + rename,
// keeping mode — a crash never leaves a half-written pf.conf.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// ModeOf is path's current permission bits, or fallback for a new file.
func ModeOf(path string, fallback os.FileMode) os.FileMode {
	if fi, err := os.Stat(path); err == nil {
		return fi.Mode().Perm()
	}
	return fallback
}
