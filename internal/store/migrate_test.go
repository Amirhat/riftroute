package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// legacyDDL is the schema exactly as v0.2.3 created it (no user_version, no
// pending_tx.format) — the database every existing install has on disk.
const legacyDDL = `
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE profiles (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 0, priority INTEGER NOT NULL DEFAULT 0, doc TEXT NOT NULL);
CREATE TABLE lists (name TEXT PRIMARY KEY, doc TEXT NOT NULL);
CREATE TABLE snapshots (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, reason TEXT NOT NULL, doc TEXT NOT NULL);
CREATE TABLE ownership (family TEXT NOT NULL, dst_cidr TEXT NOT NULL, gateway TEXT NOT NULL, iface TEXT NOT NULL, profile_id TEXT NOT NULL, created_at TEXT NOT NULL, doc TEXT NOT NULL, PRIMARY KEY (family, dst_cidr, gateway, iface));
CREATE TABLE pending_tx (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, doc TEXT NOT NULL);
CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, profile TEXT, result TEXT NOT NULL, rollback INTEGER NOT NULL DEFAULT 0, reason TEXT, doc TEXT NOT NULL);
CREATE INDEX idx_audit_ts ON audit(ts);
INSERT INTO settings(key,value) VALUES('schema_version','1');
`

func rawDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	return db
}

func userVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestFreshDatabaseMigratesToCurrentSchema(t *testing.T) {
	s := openTest(t)
	if got := userVersion(t, s.db); got != SchemaVersion() {
		t.Fatalf("user_version = %d, want %d", got, SchemaVersion())
	}
	plan := domain.Plan{Ops: []domain.PlanOp{{Kind: domain.OpAddRoute}}}
	if err := s.PutPendingTx("tx1", plan); err != nil {
		t.Fatal(err)
	}
	var format int
	if err := s.db.QueryRow(`SELECT format FROM pending_tx WHERE id='tx1'`).Scan(&format); err != nil {
		t.Fatal(err)
	}
	if format != WALFormat {
		t.Fatalf("journal row format = %d, want %d", format, WALFormat)
	}
}

// An existing v0.2.3 database — including a journal entry left by a crash —
// must migrate in place and still recover that entry.
func TestLegacyDatabaseMigratesAndKeepsJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db := rawDB(t, path)
	if _, err := db.Exec(legacyDDL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO pending_tx(id,created_at,doc) VALUES('crash-tx',?,?)`,
		time.Now().UTC().Format(time.RFC3339Nano), `{"ops":[],"inverse":[{"kind":"del_route"}]}`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	defer s.Close()
	if got := userVersion(t, s.db); got != SchemaVersion() {
		t.Fatalf("user_version = %d, want %d", got, SchemaVersion())
	}
	pend, err := s.ListPendingTx()
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if pl, ok := pend["crash-tx"]; !ok || len(pl.Inverse) != 1 {
		t.Fatalf("legacy journal entry lost across migration: %+v", pend)
	}
}

// The rollback target of an update is the PREVIOUS binary, restarted on the
// database the new one already migrated. It must keep working: its own
// statements (which never name the new column) still succeed, and what it
// writes reads back as format 1.
func TestMigratedDatabaseStaysUsableByPreviousRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rr.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	old := rawDB(t, path)
	// v0.2.3's startup DDL + journal write, verbatim in shape.
	if _, err := old.Exec(`CREATE TABLE IF NOT EXISTS pending_tx (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, doc TEXT NOT NULL)`); err != nil {
		t.Fatalf("old DDL: %v", err)
	}
	if _, err := old.Exec(`INSERT INTO pending_tx(id,created_at,doc) VALUES(?,?,?)
		 ON CONFLICT(id) DO UPDATE SET doc=excluded.doc`, "old-tx", "t", `{"ops":[]}`); err != nil {
		t.Fatalf("old journal insert: %v", err)
	}
	var id, doc string
	if err := old.QueryRow(`SELECT id, doc FROM pending_tx`).Scan(&id, &doc); err != nil {
		t.Fatalf("old journal read: %v", err)
	}
	_ = old.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.ListPendingTx(); err != nil {
		t.Fatalf("entry written by the previous release is unreadable: %v", err)
	}
}

// A database migrated by a NEWER binary with only expand steps opens fine
// (update rollback); one past a breaking step is refused, not misread.
func TestNewerSchemaExpandOpensBreakingRefuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rr.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatalf("expand-only newer schema must stay readable: %v", err)
	}
	if got := userVersion(t, s.db); got != 99 {
		t.Fatalf("an older binary must not rewrite user_version (got %d)", got)
	}
	if err := s.SetSetting(minReaderKey, "99"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	if _, err := Open(path); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("breaking newer schema: err = %v, want ErrSchemaTooNew", err)
	}
}

// Journal entries this build can't interpret are reported and kept — never
// silently dropped (the old behavior), never deleted.
func TestUnreadableJournalEntriesAreReportedAndKept(t *testing.T) {
	s := openTest(t)
	if err := s.PutPendingTx("good", domain.Plan{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO pending_tx(id,created_at,doc,format) VALUES('future','t','{}',?)`, WALFormat+1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO pending_tx(id,created_at,doc) VALUES('corrupt','t','{not json')`); err != nil {
		t.Fatal(err)
	}

	pend, err := s.ListPendingTx()
	if !errors.Is(err, ErrPendingUnreadable) {
		t.Fatalf("err = %v, want ErrPendingUnreadable", err)
	}
	if _, ok := pend["good"]; !ok || len(pend) != 1 {
		t.Fatalf("readable entries must still be returned: %+v", pend)
	}
	for _, id := range []string{"future", "corrupt"} {
		if !strings.Contains(err.Error(), id) {
			t.Fatalf("error does not name %q: %v", id, err)
		}
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pending_tx`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("unreadable entries must stay journaled: count=%d err=%v", n, err)
	}
}

func TestSnapshotIsStampedWithFormat(t *testing.T) {
	s := openTest(t)
	if err := s.SaveSnapshot(domain.Snapshot{ID: "s1", CreatedAt: time.Now(), Reason: "t"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSnapshot("s1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != SnapshotFormat {
		t.Fatalf("snapshot format = %d, want %d", got.Format, SnapshotFormat)
	}
}
