package updater

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// marker is the "an update is on probation" note swap leaves for the next
// start (or the "please roll back" note RequestRollback leaves).
type marker struct {
	From     string    `json:"from"`
	To       string    `json:"to"`
	At       time.Time `json:"at"`
	Boots    int       `json:"boots"`
	Rollback bool      `json:"rollback,omitempty"` // user-requested rollback
}

// markerMu serializes marker writes with Confirm's read-then-remove, so a
// rollback request written in between can never be removed by mistake.
var markerMu sync.Mutex

func writeMarker(dir string, m marker) error {
	markerMu.Lock()
	defer markerMu.Unlock()
	b, _ := json.Marshal(m)
	return writeFileAtomic(pendingPath(dir), b, 0o600)
}

func readMarker(dir string) (marker, bool) {
	var m marker
	b, err := os.ReadFile(pendingPath(dir))
	if err != nil || json.Unmarshal(b, &m) != nil {
		return m, false
	}
	return m, true
}

// Boot guard settings.
var (
	maxBoots = 3 // failed starts before rolling back
	// confirmWithin: a start that hasn't confirmed by then counts as failed.
	// Generous — crash recovery and route reconciliation run before serving.
	confirmWithin = 5 * time.Minute
)

// GuardEnv is what BootGuard needs. It runs before the database is opened,
// so it's free to replace it.
type GuardEnv struct {
	Current  string
	Binary   string
	StateDir string
	DBPath   string
	// DBVersion reads a database file's schema version (PRAGMA user_version).
	DBVersion func(path string) (int, error)
	// DBMinReader reads the oldest schema a database may be read with
	// (store's schema_min_reader; 0 when unset).
	DBMinReader func(path string) (int, error)
	Log         *slog.Logger
	Now         func() time.Time
	// Exit ends the process (the watchdog's failed-start exit).
	Exit func(code int)
}

// Guard is BootGuard's verdict for this start.
type Guard struct {
	// RestartNow: a rollback was just performed; exit with RestartExitCode so
	// the service manager starts the restored binary.
	RestartNow bool
	// OnConfirm runs after a successful Confirm (the updater reloads its
	// state).
	OnConfirm func()
	confirm   func()
}

// Confirm marks this start healthy: the update (if one was on probation) is
// kept. Call it once the daemon is serving.
func (g *Guard) Confirm() {
	if g == nil || g.confirm == nil {
		return
	}
	g.confirm()
	g.confirm = nil
	if g.OnConfirm != nil {
		g.OnConfirm()
	}
}

// Probation reports whether this start is an update on probation.
func (g *Guard) Probation() bool { return g != nil && g.confirm != nil }

// BootGuard runs first thing in the daemon. With no marker it does nothing.
// On the new binary it counts starts, arms a watchdog (a start that doesn't
// confirm in time exits, which counts as a failed start) and, after
// maxBoots failed starts, restores the previous binary — and the database
// backup if the old version can't read the current one — then asks for a
// restart. It needs no network.
func BootGuard(env GuardEnv) (*Guard, error) {
	if env.Now == nil {
		env.Now = time.Now
	}
	if env.Log == nil {
		env.Log = slog.Default()
	}
	if env.Exit == nil {
		env.Exit = os.Exit
	}
	m, ok := readMarker(env.StateDir)
	if !ok {
		return &Guard{}, nil
	}
	switch {
	case m.Rollback:
		env.Log.Warn("rolling back as requested", "from", m.From)
		return rollbackOrCarryOn(env, m, "you")
	case env.Current != m.To:
		// Not the new binary. Boots == 0: the swap never finished (a crash
		// between the marker and the rename) — nothing happened, try again
		// later. Otherwise the rollback already happened: record it once.
		if env.Current == m.From && m.Boots > 0 {
			recordRolledBack(env.StateDir, m.To, "health")
		}
		_ = os.Remove(pendingPath(env.StateDir))
		return &Guard{}, nil
	}
	m.Boots++
	if m.Boots > maxBoots {
		env.Log.Error("update failed its health check; rolling back", "version", m.To, "starts", m.Boots-1, "to", m.From)
		return rollbackOrCarryOn(env, m, "health")
	}
	if err := writeMarker(env.StateDir, m); err != nil {
		// The count can't be kept; the watchdog below still stops a hang.
		env.Log.Error("update probation: can't record this start", "err", err)
	}
	env.Log.Info("starting an updated daemon on probation", "version", m.To, "start", m.Boots)
	watchdog := time.AfterFunc(confirmWithin, func() {
		env.Log.Error("updated daemon did not come up in time; counting a failed start", "version", m.To)
		env.Exit(RestartExitCode)
	})
	version := m.To
	return &Guard{confirm: func() {
		watchdog.Stop()
		// Only our own probation marker: never a rollback the user asked for
		// in the meantime.
		markerMu.Lock()
		if cur, ok := readMarker(env.StateDir); ok && !cur.Rollback && cur.To == version {
			_ = os.Remove(pendingPath(env.StateDir))
		}
		markerMu.Unlock()
		// The database backup stays until the next update: a manual rollback
		// may need it.
		_, _ = updateState(env.StateDir, func(ps *persisted) {
			ps.InstalledAt, ps.RolledBackFrom, ps.RolledBackBy, ps.RollbackError = env.Now(), "", "", ""
		})
		env.Log.Info("update confirmed healthy", "version", version)
	}}, nil
}

// rollbackOrCarryOn rolls back and asks for a restart — or, if the rollback
// itself fails, records that and lets this binary start (a restart loop
// that can never succeed helps nobody).
func rollbackOrCarryOn(env GuardEnv, m marker, by string) (*Guard, error) {
	if err := rollback(env, m, by); err != nil {
		env.Log.Error("rollback failed; starting the current version", "err", err)
		_ = os.Remove(pendingPath(env.StateDir))
		_, _ = updateState(env.StateDir, func(ps *persisted) { ps.RollbackError = err.Error() })
		return &Guard{}, err
	}
	return &Guard{RestartNow: true}, nil
}

// rollback puts the previous binary back and — only if the version going
// back can't read the current database (a breaking migration raised its
// schema_min_reader past the old schema) — the pre-update database copy.
// The version rolled back from is skipped from now on.
func rollback(env GuardEnv, m marker, by string) error {
	prev := prevBinary(env.Binary)
	if !fileExists(prev) {
		return errors.New("no previous binary to roll back to")
	}
	if b := backupPath(env.StateDir); fileExists(b) && env.DBVersion != nil && env.DBMinReader != nil {
		oldSchema, err1 := env.DBVersion(b)
		minReader, err2 := env.DBMinReader(env.DBPath)
		if err1 == nil && err2 == nil && minReader > oldSchema {
			// Copy the backup beside the database first: if that fails, the
			// live database and its WAL are untouched. Then drop the WAL
			// (it belongs to the database being replaced — a crash must never
			// pair it with the restored file) and rename into place.
			tmp := env.DBPath + ".restore"
			if err := copyFileAtomic(b, tmp, 0o600); err != nil {
				_ = os.Remove(tmp)
				return fmt.Errorf("restore database: %w", err)
			}
			_ = os.Remove(env.DBPath + "-wal")
			_ = os.Remove(env.DBPath + "-shm")
			if err := os.Rename(tmp, env.DBPath); err != nil {
				return fmt.Errorf("restore database: %w", err)
			}
			env.Log.Warn("restored the database from before the update (the previous version can't read the new one)")
		}
	}
	if err := copyFileAtomic(prev, env.Binary, 0o755); err != nil {
		return fmt.Errorf("restore binary: %w", err)
	}
	_ = os.Remove(prev) // it is the current binary again
	if m.Rollback {
		_ = os.Remove(pendingPath(env.StateDir)) // nothing left to confirm
	} else {
		// The marker now says "went back to m.From"; the old binary clears
		// it on its first start.
		_ = writeMarker(env.StateDir, marker{From: m.From, To: m.To, At: env.Now(), Boots: maxBoots + 1})
	}
	recordRolledBack(env.StateDir, m.To, by)
	env.Log.Warn("rolled back", "from", m.To, "by", by)
	return nil
}

func recordRolledBack(dir, version, by string) {
	_, _ = updateState(dir, func(ps *persisted) {
		ps.RolledBackFrom, ps.RolledBackBy, ps.Skip, ps.RollbackError = version, by, version, ""
	})
}
