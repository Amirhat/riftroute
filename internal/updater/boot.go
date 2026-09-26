package updater

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
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

func writeMarker(dir string, m marker) error {
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
	maxBoots      = 3               // failed starts before rolling back
	confirmWithin = 2 * time.Minute // a start that hasn't confirmed by then failed
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
	Log       *slog.Logger
	Now       func() time.Time
	// Exit ends the process (the watchdog's failed-start exit).
	Exit func(code int)
}

// Guard is BootGuard's verdict for this start.
type Guard struct {
	// RestartNow: a rollback was just performed; exit with RestartExitCode so
	// the service manager starts the restored binary.
	RestartNow bool
	confirm    func()
}

// Confirm marks this start healthy: the update (if one was on probation) is
// kept. Call it once the daemon is fully up.
func (g *Guard) Confirm() {
	if g != nil && g.confirm != nil {
		g.confirm()
		g.confirm = nil
	}
}

// BootGuard runs first thing in the daemon. With no marker it does nothing.
// On the new binary it counts starts, arms a watchdog (a start that doesn't
// confirm in time exits, which counts as a failed start) and, after
// maxBoots failed starts, restores the previous binary — and the database
// backup if the update changed the schema — then asks for a restart. It
// needs no network.
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
	if m.Rollback {
		env.Log.Warn("rolling back as requested", "from", m.From)
		return &Guard{RestartNow: true}, rollback(env, m, "rolled back by you")
	}
	if env.Current != m.To {
		// Not the new binary: the rollback already happened (or someone
		// reinstalled). Record the outcome once and clear the marker.
		if env.Current == m.From {
			recordRolledBack(env.StateDir, m.To)
		}
		_ = os.Remove(pendingPath(env.StateDir))
		return &Guard{}, nil
	}
	m.Boots++
	if m.Boots > maxBoots {
		env.Log.Error("update failed its health check; rolling back", "version", m.To, "starts", m.Boots-1, "to", m.From)
		return &Guard{RestartNow: true}, rollback(env, m, "failed its health check")
	}
	if err := writeMarker(env.StateDir, m); err != nil {
		return &Guard{}, fmt.Errorf("update marker: %w", err)
	}
	env.Log.Info("starting an updated daemon on probation", "version", m.To, "start", m.Boots)
	watchdog := time.AfterFunc(confirmWithin, func() {
		env.Log.Error("updated daemon did not come up in time; counting a failed start", "version", m.To)
		env.Exit(RestartExitCode)
	})
	return &Guard{confirm: func() {
		watchdog.Stop()
		_ = os.Remove(pendingPath(env.StateDir))
		// Keep the database backup until the next update: a manual rollback
		// may need it.
		ps, _ := loadPersisted(env.StateDir)
		ps.InstalledAt, ps.RolledBackFrom = env.Now(), ""
		_ = savePersisted(env.StateDir, ps)
		env.Log.Info("update confirmed healthy", "version", m.To)
	}}, nil
}

// rollback puts the previous binary back and, if the update moved the
// database schema on, the pre-update database copy. The version rolled back
// from is skipped from now on.
func rollback(env GuardEnv, m marker, why string) error {
	prev := prevBinary(env.Binary)
	if _, err := os.Stat(prev); err != nil {
		_ = os.Remove(pendingPath(env.StateDir))
		return errors.New("no previous binary to roll back to")
	}
	if b := backupPath(env.StateDir); fileExists(b) && env.DBVersion != nil {
		live, err1 := env.DBVersion(env.DBPath)
		old, err2 := env.DBVersion(b)
		if err1 == nil && err2 == nil && live > old {
			if err := copyFileAtomic(b, env.DBPath, 0o600); err != nil {
				return fmt.Errorf("restore database: %w", err)
			}
			_ = os.Remove(env.DBPath + "-wal")
			_ = os.Remove(env.DBPath + "-shm")
			env.Log.Warn("restored the database from before the update (its schema had moved on)")
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
	recordRolledBack(env.StateDir, m.To)
	env.Log.Warn("rolled back", "from", m.To, "reason", why)
	return nil
}

func recordRolledBack(dir, version string) {
	ps, err := loadPersisted(dir)
	if err != nil {
		return
	}
	ps.RolledBackFrom, ps.Skip = version, version
	_ = savePersisted(dir, ps)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
