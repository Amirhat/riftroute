package buildinfo

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// Watcher remembers the executable a long-running process started from and
// reports when the file at that path has since been replaced by a different
// build — the "I installed the new version but the old one is still running"
// trap, which otherwise looks exactly like the fix not working.
type Watcher struct {
	path     string
	start    stamp
	hash     []byte // content of the executable at startup (nil if unreadable)
	running  domain.BuildInfo
	readFile func(string) (domain.BuildInfo, error)

	mu       sync.Mutex
	last     stamp
	required bool
	reason   string
}

type stamp struct {
	size int64
	mod  time.Time
}

// NewWatcher watches the running executable. It returns nil if the path can't
// be determined; a nil Watcher reports nothing.
func NewWatcher(running domain.BuildInfo) *Watcher {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	return newWatcher(exe, running, ReadFile)
}

func newWatcher(path string, running domain.BuildInfo, read func(string) (domain.BuildInfo, error)) *Watcher {
	w := &Watcher{path: path, running: running, readFile: read}
	if st, err := statOf(path); err == nil {
		w.start, w.last = st, st
		w.hash, _ = hashFile(path)
	}
	return w
}

// Path is the executable being watched ("" for a nil Watcher).
func (w *Watcher) Path() string {
	if w == nil {
		return ""
	}
	return w.path
}

// Check reports whether a restart is needed to run what is now on disk, and
// why. Cheap when nothing changed (one stat); the on-disk build is only read
// when the file's size or mtime moved.
func (w *Watcher) Check() (bool, string) {
	if w == nil || w.start == (stamp{}) {
		return false, ""
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	st, err := statOf(w.path)
	if err != nil {
		// Mid-replace (rename window) or uninstalled: not a verdict worth caching.
		return true, fmt.Sprintf("the daemon binary at %s is gone (removed or being replaced)", w.path)
	}
	if st == w.start {
		return false, ""
	}
	if st == w.last {
		return w.required, w.reason
	}
	w.last = st
	// Same bytes = same program, however it got there (touch, reinstall of
	// an identical build). Build metadata alone can't tell two dirty builds
	// of one commit apart, nor a link-stamped app from its unstamped copy.
	if h, err := hashFile(w.path); err == nil && w.hash != nil && bytes.Equal(h, w.hash) {
		w.required, w.reason = false, ""
		return w.required, w.reason
	}
	disk, err := w.readFile(w.path)
	switch {
	case err != nil:
		w.required, w.reason = true, fmt.Sprintf(
			"the daemon binary at %s was replaced since it started — restart the daemon to run it", w.path)
	case SameBuild(w.running, disk):
		w.required, w.reason = false, "" // same clean commit rebuilt
	default:
		w.required, w.reason = true, fmt.Sprintf(
			"a different build is installed at %s (%s; running %s) — restart the daemon to run it",
			w.path, Short(disk), Short(w.running))
	}
	return w.required, w.reason
}

func hashFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func statOf(path string) (stamp, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return stamp{}, err
	}
	return stamp{size: fi.Size(), mod: fi.ModTime()}, nil
}
