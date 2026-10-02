package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite: nothing to install on the host

	"github.com/Amirhat/riftroute/internal/telemetry"
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
	// Anonymous telemetry reports: one per install per day (a repeat
	// replaces it), the validated report as doc. Kept telemetryKeepDays.
	`CREATE TABLE telemetry_reports (
	   day      TEXT NOT NULL,
	   install  TEXT NOT NULL,
	   level    TEXT NOT NULL,
	   version  TEXT NOT NULL,
	   os       TEXT NOT NULL,
	   arch     TEXT NOT NULL,
	   channel  TEXT NOT NULL,
	   doc      TEXT NOT NULL,
	   received INTEGER NOT NULL,
	   PRIMARY KEY (day, install)
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
// rolled out. A read error is returned, never papered over with "go ahead".
func (s *store) advice(channel string) (update.Advice, error) {
	a := update.Advice{RolloutPercent: 100}
	var halt int
	err := s.db.QueryRow(`SELECT rollout_percent, halt FROM update_channels WHERE channel=?`, channel).Scan(&a.RolloutPercent, &halt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return a, nil
	case err != nil:
		return update.Advice{}, err
	}
	a.Halt = halt != 0
	return a, nil
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

// putReport stores a validated report, replacing the install's report for
// the same day.
func (s *store) putReport(r *telemetry.Report, now time.Time) error {
	doc, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO telemetry_reports(day, install, level, version, os, arch, channel, doc, received)
	   VALUES(?,?,?,?,?,?,?,?,?)
	   ON CONFLICT(day, install) DO UPDATE SET level=excluded.level, version=excluded.version, os=excluded.os,
	     arch=excluded.arch, channel=excluded.channel, doc=excluded.doc, received=excluded.received`,
		r.Day, r.Install, r.Level, r.App.Version, r.App.OS, r.App.Arch, r.App.Channel, string(doc), now.Unix())
	return err
}

// reports returns the reports for days from..to (YYYY-MM-DD), oldest first.
func (s *store) reports(from, to string) ([]telemetry.Report, error) {
	var out []telemetry.Report
	err := s.eachReport(from, to, false, func(r telemetry.Report) { out = append(out, r) })
	return out, err
}

// eachReport calls fn with each report for days from..to (YYYY-MM-DD),
// oldest first or, with newest, newest first — one at a time, so a summary
// over many never holds them all.
func (s *store) eachReport(from, to string, newest bool, fn func(telemetry.Report)) error {
	order := "day, received"
	if newest {
		order = "day DESC, received DESC"
	}
	rows, err := s.db.Query(`SELECT doc FROM telemetry_reports WHERE day>=? AND day<=? ORDER BY `+order, from, to)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return err
		}
		var r telemetry.Report
		if err := json.Unmarshal([]byte(doc), &r); err != nil {
			return err
		}
		fn(r)
	}
	return rows.Err()
}

// reportsOn counts the reports kept for day, and reports whether install
// has one among them.
func (s *store) reportsOn(day, install string) (n int, has bool, err error) {
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM telemetry_reports WHERE day=?`, day).Scan(&n); err != nil {
		return 0, false, err
	}
	var one int
	err = s.db.QueryRow(`SELECT COUNT(*) FROM telemetry_reports WHERE day=? AND install=?`, day, install).Scan(&one)
	return n, one > 0, err
}

// pruneReports deletes reports for days before day.
func (s *store) pruneReports(day string) error {
	_, err := s.db.Exec(`DELETE FROM telemetry_reports WHERE day<?`, day)
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
