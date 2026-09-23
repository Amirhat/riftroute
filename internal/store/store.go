// Package store is the daemon's persistence layer: a pure-Go SQLite database
// (modernc.org/sqlite, so no extra cgo on top of Wails — spec §3.3/§13). It
// owns profiles, lists, settings, the ownership map, snapshots, and the audit
// log. GUI/CLI never touch these files directly; they read state via the API.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver

	"github.com/Amirhat/riftroute/internal/domain"
)

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("store: not found")

// Store wraps the SQLite database. It is safe for concurrent use; writes are
// serialized by limiting the pool to a single connection (desktop-scale load).
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the SQLite database at path and applies
// migrations. Use ":memory:" for tests.
func Open(path string) (*Store, error) {
	dsn := path
	if path != ":memory:" {
		dsn = fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)", path)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite is a single-writer engine; one connection avoids "database is
	// locked" under the daemon's serialized mutation model.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// migration is one schema step. See migrations.
type migration struct {
	name string
	sql  string
	// breaking marks a CONTRACT step (drop/rename/reshape) that binaries
	// predating it cannot safely run against. Applying it raises the database's
	// minimum reader so those binaries refuse to open it instead of misreading.
	breaking bool
}

// migrations is APPEND-ONLY. PRAGMA user_version records how many have run, so
// an edited entry never reaches existing databases and a reordered one skips
// steps. Never change a shipped entry — add a new one.
//
// Every step must be EXPAND-only (new table/column/index, with defaults) so
// the PREVIOUS release keeps working on the same file: an update rollback
// restarts the old binary against a database the new one already migrated.
// Removing or reshaping something happens in a later release, once no
// supported binary reads it, and must be marked breaking.
var migrations = []migration{
	{name: "baseline", sql: `
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS profiles (
  id       TEXT PRIMARY KEY,
  name     TEXT NOT NULL UNIQUE,
  enabled  INTEGER NOT NULL DEFAULT 0,
  priority INTEGER NOT NULL DEFAULT 0,
  doc      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS lists (
  name TEXT PRIMARY KEY,
  doc  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS snapshots (
  id         TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  reason     TEXT NOT NULL,
  doc        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ownership (
  family     TEXT NOT NULL,
  dst_cidr   TEXT NOT NULL,
  gateway    TEXT NOT NULL,
  iface      TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  doc        TEXT NOT NULL,
  PRIMARY KEY (family, dst_cidr, gateway, iface)
);
CREATE TABLE IF NOT EXISTS pending_tx (
  id         TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  doc        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  ts       TEXT NOT NULL,
  actor    TEXT NOT NULL,
  action   TEXT NOT NULL,
  profile  TEXT,
  result   TEXT NOT NULL,
  rollback INTEGER NOT NULL DEFAULT 0,
  reason   TEXT,
  doc      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
`},
	// The journal's doc format. Pre-existing rows (and rows an older binary
	// inserts without naming the column) are format 1 — today's domain.Plan.
	{name: "pending_tx.format", sql: `ALTER TABLE pending_tx ADD COLUMN format INTEGER NOT NULL DEFAULT 1`},
}

// SchemaVersion is the schema this binary migrates databases to.
func SchemaVersion() int { return len(migrations) }

// minReaderKey records the oldest schema version that can still read the
// database safely (raised by breaking migrations).
const minReaderKey = "schema_min_reader"

// ErrSchemaTooNew is returned by Open when the database was migrated by a newer
// RiftRoute with a breaking change this binary cannot read.
var ErrSchemaTooNew = errors.New("store: database requires a newer RiftRoute")

func (s *Store) migrate() error {
	var have int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&have); err != nil {
		return fmt.Errorf("migrate: read user_version: %w", err)
	}
	if have > len(migrations) {
		// Written by a newer binary (e.g. we are the rollback target of an
		// update). Expand-only schemas stay readable; refuse only if a breaking
		// step raised the minimum reader past us.
		v, ok, err := s.GetSetting(minReaderKey)
		if err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		if n, _ := strconv.Atoi(v); ok && n > len(migrations) {
			return fmt.Errorf("%w: schema %d needs a reader of schema %d+, this build reads %d",
				ErrSchemaTooNew, have, n, len(migrations))
		}
		return nil
	}
	for i := have; i < len(migrations); i++ {
		m := migrations[i]
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("migrate %d (%s): %w", i+1, m.name, err)
		}
		if _, err := tx.Exec(m.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migrate %d (%s): %w", i+1, m.name, err)
		}
		if m.breaking {
			if _, err := tx.Exec(
				`INSERT INTO settings(key,value) VALUES(?,?)
				 ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
				minReaderKey, strconv.Itoa(i+1)); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("migrate %d (%s): min reader: %w", i+1, m.name, err)
			}
		}
		// PRAGMA takes no bound parameters; i+1 is an int we control.
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migrate %d (%s): set version: %w", i+1, m.name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migrate %d (%s): commit: %w", i+1, m.name, err)
		}
	}
	return nil
}

// --- Settings ---

// GetSetting returns a setting value and whether it exists.
func (s *Store) GetSetting(key string) (string, bool, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// SetSetting upserts a setting value.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO settings(key,value) VALUES(?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// --- Profiles ---

// ListProfiles returns all profiles ordered by priority then name.
func (s *Store) ListProfiles() ([]domain.Profile, error) {
	rows, err := s.db.Query(`SELECT doc FROM profiles ORDER BY priority, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Profile
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		var p domain.Profile
		if err := json.Unmarshal([]byte(doc), &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetProfile returns a profile by name.
func (s *Store) GetProfile(name string) (domain.Profile, error) {
	var doc string
	err := s.db.QueryRow(`SELECT doc FROM profiles WHERE name=?`, name).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Profile{}, ErrNotFound
	}
	if err != nil {
		return domain.Profile{}, err
	}
	var p domain.Profile
	return p, json.Unmarshal([]byte(doc), &p)
}

// UpsertProfile inserts or replaces a profile (keyed by id).
func (s *Store) UpsertProfile(p domain.Profile) error {
	doc, err := json.Marshal(p)
	if err != nil {
		return err
	}
	enabled := 0
	if p.Enabled {
		enabled = 1
	}
	_, err = s.db.Exec(
		`INSERT INTO profiles(id,name,enabled,priority,doc) VALUES(?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET name=excluded.name, enabled=excluded.enabled, priority=excluded.priority, doc=excluded.doc`,
		p.ID, p.Name, enabled, p.Priority, string(doc))
	return err
}

// SetProfileEnabled flips a profile's enabled flag (and its stored doc) by name.
func (s *Store) SetProfileEnabled(name string, enabled bool) error {
	p, err := s.GetProfile(name)
	if err != nil {
		return err
	}
	p.Enabled = enabled
	return s.UpsertProfile(p)
}

// DeleteProfile removes a profile by name.
func (s *Store) DeleteProfile(name string) error {
	_, err := s.db.Exec(`DELETE FROM profiles WHERE name=?`, name)
	return err
}

// --- Lists ---

// ListLists returns all reusable lists ordered by name.
func (s *Store) ListLists() ([]domain.List, error) {
	rows, err := s.db.Query(`SELECT doc FROM lists ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.List
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		var l domain.List
		if err := json.Unmarshal([]byte(doc), &l); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// GetList returns a list by name.
func (s *Store) GetList(name string) (domain.List, error) {
	var doc string
	err := s.db.QueryRow(`SELECT doc FROM lists WHERE name=?`, name).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.List{}, ErrNotFound
	}
	if err != nil {
		return domain.List{}, err
	}
	var l domain.List
	return l, json.Unmarshal([]byte(doc), &l)
}

// UpsertList inserts or replaces a list (keyed by name).
func (s *Store) UpsertList(l domain.List) error {
	doc, err := json.Marshal(l)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO lists(name,doc) VALUES(?,?)
		 ON CONFLICT(name) DO UPDATE SET doc=excluded.doc`, l.Name, string(doc))
	return err
}

// DeleteList removes a list by name.
func (s *Store) DeleteList(name string) error {
	_, err := s.db.Exec(`DELETE FROM lists WHERE name=?`, name)
	return err
}

// --- Split-DNS persistence (settings-backed) ---

const splitDNSKey = "split_dns"

// SaveSplitDNS persists the per-domain resolver routes so they survive daemon
// restarts (the manager re-applies them on startup).
func (s *Store) SaveSplitDNS(routes []domain.SplitDNSRoute) error {
	doc, err := json.Marshal(routes)
	if err != nil {
		return err
	}
	return s.SetSetting(splitDNSKey, string(doc))
}

// LoadSplitDNS returns the persisted split-DNS routes (empty when unset).
func (s *Store) LoadSplitDNS() ([]domain.SplitDNSRoute, error) {
	v, ok, err := s.GetSetting(splitDNSKey)
	if err != nil || !ok || v == "" {
		return nil, err
	}
	var routes []domain.SplitDNSRoute
	if err := json.Unmarshal([]byte(v), &routes); err != nil {
		return nil, err
	}
	return routes, nil
}

// --- Audit ---

// AppendAudit writes an audit event and returns its assigned id.
func (s *Store) AppendAudit(ev domain.AuditEvent) (int64, error) {
	if ev.TS.IsZero() {
		ev.TS = time.Now()
	}
	doc, err := json.Marshal(ev)
	if err != nil {
		return 0, err
	}
	rb := 0
	if ev.Rollback {
		rb = 1
	}
	res, err := s.db.Exec(
		`INSERT INTO audit(ts,actor,action,profile,result,rollback,reason,doc) VALUES(?,?,?,?,?,?,?,?)`,
		ev.TS.Format(time.RFC3339Nano), string(ev.Actor), ev.Action, ev.Profile, ev.Result, rb, ev.Reason, string(doc))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListAudit returns audit events at or after since (zero = all), newest first,
// capped at limit (<=0 = 200).
func (s *Store) ListAudit(since time.Time, limit int) ([]domain.AuditEvent, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.Query(
		`SELECT id, doc FROM audit WHERE ts >= ? ORDER BY id DESC LIMIT ?`,
		since.Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AuditEvent
	for rows.Next() {
		var (
			id  int64
			doc string
		)
		if err := rows.Scan(&id, &doc); err != nil {
			return nil, err
		}
		var ev domain.AuditEvent
		if err := json.Unmarshal([]byte(doc), &ev); err != nil {
			return nil, err
		}
		ev.ID = id // the autoincrement id is authoritative (doc is marshaled pre-insert)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// --- Snapshots ---

// SaveSnapshot persists a full-state snapshot.
func (s *Store) SaveSnapshot(snap domain.Snapshot) error {
	if snap.Format == 0 {
		snap.Format = SnapshotFormat
	}
	doc, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO snapshots(id,created_at,reason,doc) VALUES(?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET doc=excluded.doc`,
		snap.ID, snap.CreatedAt.Format(time.RFC3339Nano), snap.Reason, string(doc))
	return err
}

// ListSnapshots returns snapshot metadata, newest first.
func (s *Store) ListSnapshots() ([]domain.Snapshot, error) {
	rows, err := s.db.Query(`SELECT doc FROM snapshots ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Snapshot
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		var snap domain.Snapshot
		if err := json.Unmarshal([]byte(doc), &snap); err != nil {
			return nil, err
		}
		out = append(out, snap)
	}
	return out, rows.Err()
}

// PruneSnapshots deletes all but the newest keep snapshots.
func (s *Store) PruneSnapshots(keep int) error {
	if keep <= 0 {
		return nil
	}
	_, err := s.db.Exec(
		`DELETE FROM snapshots WHERE id NOT IN
		 (SELECT id FROM snapshots ORDER BY created_at DESC LIMIT ?)`, keep)
	return err
}

// GetSnapshot returns a snapshot by id.
func (s *Store) GetSnapshot(id string) (domain.Snapshot, error) {
	var doc string
	err := s.db.QueryRow(`SELECT doc FROM snapshots WHERE id=?`, id).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Snapshot{}, ErrNotFound
	}
	if err != nil {
		return domain.Snapshot{}, err
	}
	var snap domain.Snapshot
	return snap, json.Unmarshal([]byte(doc), &snap)
}

// --- Ownership map (managed routes) ---

// ListOwned returns the ownership set: every route RiftRoute believes it owns.
// This is the macOS source of truth for ownership and a cross-check on Linux.
func (s *Store) ListOwned() ([]domain.ManagedRoute, error) {
	rows, err := s.db.Query(`SELECT doc FROM ownership ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ManagedRoute
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		var mr domain.ManagedRoute
		if err := json.Unmarshal([]byte(doc), &mr); err != nil {
			return nil, err
		}
		out = append(out, mr)
	}
	return out, rows.Err()
}

// AddOwned records a managed route in the ownership map.
func (s *Store) AddOwned(mr domain.ManagedRoute) error {
	doc, err := json.Marshal(mr)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO ownership(family,dst_cidr,gateway,iface,profile_id,created_at,doc) VALUES(?,?,?,?,?,?,?)
		 ON CONFLICT(family,dst_cidr,gateway,iface) DO UPDATE SET profile_id=excluded.profile_id, doc=excluded.doc`,
		string(mr.Family), mr.DstCIDR, mr.Gateway, mr.Iface, mr.ProfileID, mr.CreatedAt.Format(time.RFC3339Nano), string(doc))
	return err
}

// DelOwned removes a managed route from the ownership map.
func (s *Store) DelOwned(mr domain.ManagedRoute) error {
	_, err := s.db.Exec(
		`DELETE FROM ownership WHERE family=? AND dst_cidr=? AND gateway=? AND iface=?`,
		string(mr.Family), mr.DstCIDR, mr.Gateway, mr.Iface)
	return err
}

// ClearOwned empties the ownership map (used by panic/uninstall).
func (s *Store) ClearOwned() error {
	_, err := s.db.Exec(`DELETE FROM ownership`)
	return err
}

// WALFormat and SnapshotFormat are the doc formats this binary writes — and
// the newest it can read. Bump one (and teach the reader the old shape) when
// the stored JSON changes incompatibly; an older binary then refuses the entry
// instead of misreading it.
const (
	WALFormat      = 1
	SnapshotFormat = 1
)

// ErrPendingUnreadable reports journal entries this binary cannot interpret
// (written by a newer RiftRoute, or corrupt). They are left in place — never
// silently skipped, never deleted — so the binary that wrote them can still
// recover them.
var ErrPendingUnreadable = errors.New("store: unreadable pending transactions")

// PutPendingTx write-ahead-logs a transaction's plan BEFORE the kernel is
// mutated, so a crash/power-loss mid-apply (or mid-probation) can be rolled back
// on the next startup — critical on macOS, where kernel routes carry no owner
// tag and can't otherwise be reattributed. Cleared once the tx commits/reverts.
func (s *Store) PutPendingTx(id string, plan domain.Plan) error {
	doc, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO pending_tx(id,created_at,doc,format) VALUES(?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET doc=excluded.doc, format=excluded.format`,
		id, time.Now().UTC().Format(time.RFC3339Nano), string(doc), WALFormat)
	return err
}

// ClearPendingTx removes a resolved transaction's journal entry.
func (s *Store) ClearPendingTx(id string) error {
	_, err := s.db.Exec(`DELETE FROM pending_tx WHERE id=?`, id)
	return err
}

// ListPendingTx returns transactions that were in flight when the daemon last
// stopped (crash recovery replays their inverse to fail-safe). Entries it
// cannot read are omitted from the map AND reported via ErrPendingUnreadable,
// alongside the readable ones.
func (s *Store) ListPendingTx() (map[string]domain.Plan, error) {
	rows, err := s.db.Query(`SELECT id, format, doc FROM pending_tx`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]domain.Plan{}
	var bad []string
	for rows.Next() {
		var (
			id, doc string
			format  int
		)
		if err := rows.Scan(&id, &format, &doc); err != nil {
			return nil, err
		}
		if format > WALFormat {
			bad = append(bad, fmt.Sprintf("%s (format %d, this build reads %d)", id, format, WALFormat))
			continue
		}
		var pl domain.Plan
		if err := json.Unmarshal([]byte(doc), &pl); err != nil {
			bad = append(bad, fmt.Sprintf("%s (corrupt: %v)", id, err))
			continue
		}
		out[id] = pl
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(bad) > 0 {
		return out, fmt.Errorf("%w: %s", ErrPendingUnreadable, strings.Join(bad, "; "))
	}
	return out, nil
}
