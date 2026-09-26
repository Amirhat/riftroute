package updater

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// persisted is the updater's memory across restarts and database restores —
// a file beside the database, never inside it. Every write is
// read-modify-write under stateMu, so the boot guard and the updater in the
// same process can't overwrite each other's fields.
type persisted struct {
	Bucket         int       `json:"bucket"`
	Skip           string    `json:"skip,omitempty"`
	RolledBackFrom string    `json:"rolled_back_from,omitempty"`
	RolledBackBy   string    `json:"rolled_back_by,omitempty"` // "health" | "you"
	RollbackError  string    `json:"rollback_error,omitempty"`
	InstalledAt    time.Time `json:"installed_at,omitzero"`
	LastCheck      time.Time `json:"last_check,omitzero"`
	// LastAdvice is the update server's last word on the newest release it
	// served; a GitHub copy of that release obeys it too.
	LastAdvice struct {
		Version        string    `json:"version,omitempty"`
		RolloutPercent int       `json:"rollout_percent"`
		Halt           bool      `json:"halt"`
		At             time.Time `json:"at,omitzero"`
	} `json:"last_advice"`
}

var stateMu sync.Mutex

func statePath(dir string) string   { return filepath.Join(dir, "update-state.json") }
func stagingDir(dir string) string  { return filepath.Join(dir, "update-staging") }
func backupPath(dir string) string  { return filepath.Join(dir, "update-backup.db") }
func prevBinary(bin string) string  { return bin + ".prev" }
func pendingPath(dir string) string { return filepath.Join(dir, "update-pending.json") }

// loadPersisted reads the state (creating it, with a fresh rollout bucket, if
// it's missing or unreadable).
func loadPersisted(dir string) (persisted, error) {
	stateMu.Lock()
	defer stateMu.Unlock()
	return loadLocked(dir)
}

func loadLocked(dir string) (persisted, error) {
	var ps persisted
	b, err := os.ReadFile(statePath(dir))
	switch {
	case err == nil:
		if json.Unmarshal(b, &ps) == nil && ps.Bucket >= 0 && ps.Bucket < 100 {
			return ps, nil
		}
		fallthrough // unreadable: start over with a fresh bucket
	case errors.Is(err, os.ErrNotExist):
		var n [2]byte
		if _, err := rand.Read(n[:]); err != nil {
			return ps, err
		}
		ps = persisted{Bucket: int(binary.BigEndian.Uint16(n[:]) % 100)}
		return ps, saveLocked(dir, ps)
	default:
		return ps, err
	}
}

// updateState applies f to the state on disk and returns the result.
func updateState(dir string, f func(*persisted)) (persisted, error) {
	stateMu.Lock()
	defer stateMu.Unlock()
	ps, err := loadLocked(dir)
	if err != nil {
		return ps, err
	}
	f(&ps)
	return ps, saveLocked(dir, ps)
}

func saveLocked(dir string, ps persisted) error {
	b, _ := json.MarshalIndent(ps, "", "  ")
	return writeFileAtomic(statePath(dir), b, 0o600)
}

// ---------------------------------------------------------------- files

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	return finishAtomic(tmp, path, mode)
}

// copyFileAtomic copies src to dst through a temporary file in dst's
// directory, so dst is always either the old or the new file.
func copyFileAtomic(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	return finishAtomic(tmp, dst, mode)
}

func finishAtomic(tmp *os.File, dst string, mode os.FileMode) error {
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
