package server

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite: nothing to install on the host

	"github.com/Amirhat/riftroute/internal/update"
)

// store is the server's SQLite database. Sessions are kept by the SHA-256 of
// their token, so a copy of the file never yields a usable login.
type store struct {
	db   *sql.DB
	path string
}

// migrations is append-only (PRAGMA user_version counts them); see the same
// rule in internal/store.
var migrations = []string{
	`CREATE TABLE sessions (
	   token_hash TEXT PRIMARY KEY,
	   csrf       TEXT NOT NULL,
	   created_at INTEGER NOT NULL,
	   expires_at INTEGER NOT NULL
	 );
	 CREATE INDEX idx_sessions_expiry ON sessions(expires_at);`,
	// Devices that have signed in before: exempt from the global login cap
	// (never from their own), so a flood can't lock the owner out.
	`CREATE TABLE devices (
	   token_hash TEXT PRIMARY KEY,
	   created_at INTEGER NOT NULL,
	   last_seen  INTEGER NOT NULL
	 );`,
	// Unsigned rollout advice per update channel (the signed manifest lives on
	// disk). It can only hold an update back.
	`CREATE TABLE update_channels (
	   channel         TEXT PRIMARY KEY,
	   rollout_percent INTEGER NOT NULL,
	   halt            INTEGER NOT NULL,
	   updated_at      INTEGER NOT NULL
	 );`,
}

func openStore(path string) (*store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &store{db: db, path: path}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *store) migrate() error {
	var have int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&have); err != nil {
		return err
	}
	for i := have; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migrate %d: %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *store) close() error { return s.db.Close() }

func (s *store) createSession(tokenHash, csrf string, now, expires time.Time) error {
	_, err := s.db.Exec(`INSERT INTO sessions(token_hash, csrf, created_at, expires_at) VALUES(?,?,?,?)`,
		tokenHash, csrf, now.Unix(), expires.Unix())
	return err
}

// session returns the session's CSRF token if it exists and hasn't expired.
func (s *store) session(tokenHash string, now time.Time) (string, bool, error) {
	var csrf string
	err := s.db.QueryRow(`SELECT csrf FROM sessions WHERE token_hash=? AND expires_at>?`, tokenHash, now.Unix()).Scan(&csrf)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return csrf, err == nil, err
}

func (s *store) deleteSession(tokenHash string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash=?`, tokenHash)
	return err
}

func (s *store) pruneSessions(now time.Time) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at<=?`, now.Unix())
	return err
}

// revokeAll signs out every session and forgets every device.
func (s *store) revokeAll() error {
	_, err := s.db.Exec(`DELETE FROM sessions; DELETE FROM devices;`)
	return err
}

func (s *store) addDevice(tokenHash string, now time.Time) error {
	_, err := s.db.Exec(`INSERT INTO devices(token_hash, created_at, last_seen) VALUES(?,?,?)`, tokenHash, now.Unix(), now.Unix())
	return err
}

// knownDevice reports whether a device token was issued and is still fresh.
func (s *store) knownDevice(tokenHash string, now time.Time) bool {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE token_hash=? AND last_seen>?`, tokenHash, now.Add(-deviceTTL).Unix()).Scan(&n)
	return n == 1
}

func (s *store) touchDevice(tokenHash string, now time.Time) error {
	_, err := s.db.Exec(`UPDATE devices SET last_seen=? WHERE token_hash=?`, now.Unix(), tokenHash)
	return err
}

func (s *store) pruneDevices(now time.Time) error {
	_, err := s.db.Exec(`DELETE FROM devices WHERE last_seen<=?`, now.Add(-deviceTTL).Unix())
	return err
}

// advice is a channel's rollout advice; a channel nobody configured is fully
// rolled out.
func (s *store) advice(channel string) update.Advice {
	a := update.Advice{RolloutPercent: 100}
	var halt int
	if err := s.db.QueryRow(`SELECT rollout_percent, halt FROM update_channels WHERE channel=?`, channel).Scan(&a.RolloutPercent, &halt); err == nil {
		a.Halt = halt != 0
	}
	return a
}

func (s *store) setAdvice(channel string, a update.Advice, now time.Time) error {
	halt := 0
	if a.Halt {
		halt = 1
	}
	_, err := s.db.Exec(`INSERT INTO update_channels(channel, rollout_percent, halt, updated_at) VALUES(?,?,?,?)
	   ON CONFLICT(channel) DO UPDATE SET rollout_percent=excluded.rollout_percent, halt=excluded.halt, updated_at=excluded.updated_at`,
		channel, a.RolloutPercent, halt, now.Unix())
	return err
}

func (s *store) activeSessions(now time.Time) int {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE expires_at>?`, now.Unix()).Scan(&n)
	return n
}

// size is the database's footprint on disk (main file + WAL).
func (s *store) size() int64 {
	var total int64
	for _, p := range []string{s.path, s.path + "-wal"} {
		if fi, err := os.Stat(p); err == nil {
			total += fi.Size()
		}
	}
	return total
}
