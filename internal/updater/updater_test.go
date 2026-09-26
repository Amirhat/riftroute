package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/update"
)

// rewrite sends every request to the test server, keeping the path, so the
// updater sees (and checks) the real production URLs.
type rewrite struct{ target *url.URL }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host = r.target.Scheme, r.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

// fakeDaemon is a tiny executable standing in for riftrouted: it prints its
// version for -version.
func fakeDaemon(version string) []byte {
	return []byte("#!/bin/sh\necho \"" + version + " (abc1234, 2026-10-01)\"\n")
}

func tarball(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		b    []byte
	}{{"riftroute", []byte("#!/bin/sh\n")}, {name, body}} {
		_ = tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o755, Size: int64(len(f.b)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(f.b)
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

type fakeRelease struct {
	t          *testing.T
	priv       ed25519.PrivateKey
	keys       map[string]ed25519.PublicKey
	version    string
	tgz        []byte
	advice     update.Advice
	serverDown atomic.Bool
	tamper     atomic.Bool
	downloads  atomic.Int32
	srv        *httptest.Server
}

func newFakeRelease(t *testing.T, version string, daemon []byte) *fakeRelease {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := &fakeRelease{t: t, priv: priv, keys: map[string]ed25519.PublicKey{update.KeyID(pub): pub}, version: version,
		tgz: tarball(t, "riftrouted", daemon), advice: update.Advice{RolloutPercent: 100}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/update/stable", func(w http.ResponseWriter, r *http.Request) {
		if f.serverDown.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		raw, sig := f.signed()
		_ = json.NewEncoder(w).Encode(serverResponse{Manifest: base64.StdEncoding.EncodeToString(raw),
			Signature: base64.StdEncoding.EncodeToString(sig), Advice: f.advice})
	})
	mux.HandleFunc("/Amirhat/riftroute/releases/latest/download/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := f.signed()
		_, _ = w.Write(raw)
	})
	mux.HandleFunc("/Amirhat/riftroute/releases/latest/download/manifest.json.sig", func(w http.ResponseWriter, r *http.Request) {
		_, sig := f.signed()
		_, _ = w.Write(sig)
	})
	mux.HandleFunc("/Amirhat/riftroute/releases/download/", func(w http.ResponseWriter, r *http.Request) {
		f.downloads.Add(1)
		b := f.tgz
		if f.tamper.Load() {
			b = append([]byte{}, b...)
			b[len(b)-1] ^= 0xff
		}
		_, _ = w.Write(b)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRelease) signed() ([]byte, []byte) {
	sum := sha256.Sum256(f.tgz)
	m := update.Manifest{Schema: 1, Channel: "stable", Version: f.version, Published: time.Unix(0, 0).UTC(),
		NotesURL: "https://github.com/Amirhat/riftroute/releases/tag/v" + f.version,
		Assets: []update.ManifestAsset{{OS: "darwin", Arch: "arm64", Kind: "tarball",
			URL:    "https://github.com/Amirhat/riftroute/releases/download/v" + f.version + "/riftroute_" + f.version + "_darwin_arm64.tar.gz",
			SHA256: hex.EncodeToString(sum[:]), Size: int64(len(f.tgz))}}}
	raw, _ := json.Marshal(m)
	sig, _ := json.Marshal(update.Sign(f.priv, raw))
	return raw, sig
}

type harness struct {
	u        *Updater
	env      Env
	restarts atomic.Int32
	idle     atomic.Bool
	mode     atomic.Value
	selfErr  error // SelfTest runs synchronously inside Check
}

func newHarness(t *testing.T, f *fakeRelease, current string) *harness {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "riftrouted")
	if err := os.WriteFile(bin, fakeDaemon(current), 0o755); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "riftroute.db")
	_ = os.WriteFile(db, []byte("live db"), 0o600)
	h := &harness{}
	h.idle.Store(true)
	h.mode.Store(domain.UpdateAuto)
	u, _ := url.Parse(f.srv.URL)
	h.env = Env{
		Current: current, Channel: "stable", ServerURL: DefaultServerURL, FallbackURL: DefaultFallbackURL,
		Keys: f.keys, GOOS: "darwin", GOARCH: "arm64", Binary: bin, StateDir: dir, DBPath: db,
		SelfUpdatable: true, HTTP: &http.Client{Transport: rewrite{u}},
		Mode: func() domain.UpdateMode { return h.mode.Load().(domain.UpdateMode) },
		Idle: func() (bool, string) {
			if h.idle.Load() {
				return true, ""
			}
			return false, "a change is awaiting confirmation"
		},
		BackupDB: func(p string) error { return os.WriteFile(p, []byte("db copy"), 0o600) },
		SelfTest: func(ctx context.Context, bin, db string) error {
			return h.selfErr
		},
		Restart: func() { h.restarts.Add(1) },
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	var err error
	h.u, err = New(h.env)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestUpdateStagesThenInstallsAtAQuietMoment(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	h := newHarness(t, f, "0.2.6")
	h.idle.Store(false)
	st := h.u.Check(context.Background(), false)
	if st.Action != "install" || st.Staged != "0.2.7" || st.Source != "server" {
		t.Fatalf("after check: %+v", st)
	}
	h.u.maybeInstall(context.Background())
	if st := h.u.Status(); st.State != "waiting" || !strings.Contains(st.Reason, "awaiting confirmation") || h.restarts.Load() != 0 {
		t.Fatalf("busy daemon: %+v restarts=%d", st, h.restarts.Load())
	}
	h.idle.Store(true)
	h.u.maybeInstall(context.Background())
	if h.restarts.Load() != 1 {
		t.Fatal("no restart after installing")
	}
	if b, _ := os.ReadFile(h.env.Binary); !bytes.Equal(b, fakeDaemon("0.2.7")) {
		t.Fatal("binary not replaced")
	}
	if b, _ := os.ReadFile(prevBinary(h.env.Binary)); !bytes.Equal(b, fakeDaemon("0.2.6")) {
		t.Fatal("previous binary not kept")
	}
	if m, ok := readMarker(h.env.StateDir); !ok || m.From != "0.2.6" || m.To != "0.2.7" {
		t.Fatalf("marker %+v %v", m, ok)
	}
	if !fileExists(backupPath(h.env.StateDir)) {
		t.Fatal("database not backed up before the swap")
	}
}

func TestFallsBackToGitHubButNeverPastAHalt(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	h := newHarness(t, f, "0.2.6")
	f.serverDown.Store(true)
	if st := h.u.Check(context.Background(), false); st.Source != "github" || st.Action != "install" {
		t.Fatalf("fallback: %+v", st)
	}
	f2 := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	f2.advice = update.Advice{RolloutPercent: 100, Halt: true}
	h2 := newHarness(t, f2, "0.2.6")
	if st := h2.u.Check(context.Background(), false); st.Action != "hold" || st.Source != "server" || st.Staged != "" || f2.downloads.Load() != 0 {
		t.Fatalf("halt: %+v downloads=%d", st, f2.downloads.Load())
	}
}

func TestTamperedDownloadIsRefusedAndRetriedLater(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	h := newHarness(t, f, "0.2.6")
	f.tamper.Store(true)
	st := h.u.Check(context.Background(), false)
	if st.Staged != "" || st.State != "error" || !strings.Contains(st.Error, "signed checksum") {
		t.Fatalf("tampered: %+v", st)
	}
	f.tamper.Store(false) // a network glitch isn't the release's fault
	if st := h.u.Check(context.Background(), false); st.Staged != "0.2.7" {
		t.Fatalf("retry: %+v", st)
	}
}

func TestReleaseThatFailsItsSelfTestIsSkipped(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	h := newHarness(t, f, "0.2.6")
	h.selfErr = errors.New("migration 9 failed")
	if st := h.u.Check(context.Background(), false); st.Staged != "" || !strings.Contains(st.Error, "self-test") {
		t.Fatalf("self-test failure: %+v", st)
	}
	h.selfErr = nil
	if st := h.u.Check(context.Background(), false); st.Action != "none" || f.downloads.Load() != 1 {
		t.Fatalf("failed release offered again: %+v downloads=%d", st, f.downloads.Load())
	}
}

// A binary that says it's a different version than the manifest is refused.
func TestStagedBinaryMustBeTheSignedVersion(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.8"))
	h := newHarness(t, f, "0.2.6")
	if st := h.u.Check(context.Background(), false); st.Staged != "" || !strings.Contains(st.Error, "manifest says 0.2.7") {
		t.Fatalf("version mismatch: %+v", st)
	}
}

func TestNotifyModeWaitsForTheUser(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	h := newHarness(t, f, "0.2.6")
	h.mode.Store(domain.UpdateNotify)
	if st := h.u.Check(context.Background(), false); st.Action != "notify" || st.Staged != "" {
		t.Fatalf("notify: %+v", st)
	}
	h.u.maybeInstall(context.Background())
	if h.restarts.Load() != 0 {
		t.Fatal("installed without being asked")
	}
	if _, err := h.u.InstallNow(context.Background()); err != nil || h.restarts.Load() != 1 {
		t.Fatalf("install now: %v restarts=%d", err, h.restarts.Load())
	}
}

func TestDevBuildsAndManagedInstallsAreNotReplaced(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	h := newHarness(t, f, "0.2.6-3-gabc1234")
	if st := h.u.Check(context.Background(), false); st.Action != "notify" {
		t.Fatalf("dev build: %+v", st)
	}
	if _, err := h.u.InstallNow(context.Background()); err == nil {
		t.Fatal("dev build installed a release over itself")
	}
}

func TestRolloutBucketIsStable(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	h := newHarness(t, f, "0.2.6")
	u2, err := New(h.env)
	if err != nil || u2.bucket() != h.u.bucket() {
		t.Fatalf("bucket changed across restarts: %d vs %d (%v)", u2.bucket(), h.u.bucket(), err)
	}
}

// ---------------------------------------------------------------- boot guard

func guardEnv(h *harness, current string) GuardEnv {
	return GuardEnv{Current: current, Binary: h.env.Binary, StateDir: h.env.StateDir, DBPath: h.env.DBPath,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Exit: func(int) {}}
}

// installed runs a full install to leave the files a real swap leaves.
func installed(t *testing.T) *harness {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	h := newHarness(t, f, "0.2.6")
	h.u.Check(context.Background(), false)
	h.u.maybeInstall(context.Background())
	if h.restarts.Load() != 1 {
		t.Fatal("setup: install didn't happen")
	}
	return h
}

func TestHealthyUpdateIsConfirmed(t *testing.T) {
	h := installed(t)
	g, err := BootGuard(guardEnv(h, "0.2.7"))
	if err != nil || g.RestartNow {
		t.Fatalf("guard: %v %+v", err, g)
	}
	g.Confirm()
	if _, ok := readMarker(h.env.StateDir); ok {
		t.Fatal("marker left after confirming")
	}
	u2, _ := New(h.env)
	if u2.Status().InstalledAt.IsZero() {
		t.Fatal("install time not recorded")
	}
}

func TestUpdateThatNeverComesUpIsRolledBack(t *testing.T) {
	h := installed(t)
	env := guardEnv(h, "0.2.7")
	for i := 1; i <= maxBoots; i++ { // crashes before confirming, three times
		g, err := BootGuard(env)
		if err != nil || g.RestartNow {
			t.Fatalf("start %d: %v %+v", i, err, g)
		}
	}
	g, err := BootGuard(env)
	if err != nil || !g.RestartNow {
		t.Fatalf("4th start should roll back: %v %+v", err, g)
	}
	if b, _ := os.ReadFile(h.env.Binary); !bytes.Equal(b, fakeDaemon("0.2.6")) {
		t.Fatal("previous binary not restored")
	}
	if fileExists(prevBinary(h.env.Binary)) {
		t.Fatal(".prev kept after it was restored")
	}
	// The old binary starts: the marker is cleared and the outcome recorded.
	if g, err := BootGuard(guardEnv(h, "0.2.6")); err != nil || g.RestartNow {
		t.Fatalf("old binary's start: %v %+v", err, g)
	}
	if _, ok := readMarker(h.env.StateDir); ok {
		t.Fatal("marker left behind")
	}
	h.env.Current = "0.2.6"
	u2, _ := New(h.env)
	if st := u2.Status(); st.RolledBackFrom != "0.2.7" {
		t.Fatalf("rollback not recorded: %+v", st)
	}
	if st := u2.Check(context.Background(), false); st.Action != "none" {
		t.Fatalf("rolled-back version offered again: %+v", st)
	}
}

func TestRollbackRestoresTheDatabaseOnlyWhenTheSchemaMoved(t *testing.T) {
	for _, moved := range []bool{false, true} {
		h := installed(t)
		env := guardEnv(h, "0.2.7")
		env.DBVersion = func(p string) (int, error) {
			if p == h.env.DBPath && moved {
				return 5, nil
			}
			return 4, nil
		}
		for i := 0; i <= maxBoots; i++ {
			_, _ = BootGuard(env)
		}
		b, _ := os.ReadFile(h.env.DBPath)
		if got := string(b) == "db copy"; got != moved {
			t.Errorf("schema moved=%v: database restored=%v", moved, got)
		}
	}
}

func TestHungStartCountsAsAFailedStart(t *testing.T) {
	old := confirmWithin
	confirmWithin = 20 * time.Millisecond
	t.Cleanup(func() { confirmWithin = old })
	h := installed(t)
	env := guardEnv(h, "0.2.7")
	exited := make(chan int, 1)
	env.Exit = func(code int) { exited <- code }
	if _, err := BootGuard(env); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-exited:
		if code != RestartExitCode {
			t.Fatalf("exit code %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog never fired for a start that didn't confirm")
	}
}

func TestUserRollback(t *testing.T) {
	h := installed(t)
	g, _ := BootGuard(guardEnv(h, "0.2.7"))
	g.Confirm()
	h.env.Current = "0.2.7"
	u2, _ := New(h.env)
	if !u2.Status().CanRollBack {
		t.Fatal("rollback not offered while .prev is kept")
	}
	if err := u2.RequestRollback(); err != nil || h.restarts.Load() != 2 {
		t.Fatalf("request: %v restarts=%d", err, h.restarts.Load())
	}
	g2, err := BootGuard(guardEnv(h, "0.2.7"))
	if err != nil || !g2.RestartNow {
		t.Fatalf("rollback start: %v %+v", err, g2)
	}
	if b, _ := os.ReadFile(h.env.Binary); !bytes.Equal(b, fakeDaemon("0.2.6")) {
		t.Fatal("previous binary not restored")
	}
	if g3, _ := BootGuard(guardEnv(h, "0.2.6")); g3.RestartNow {
		t.Fatal("restored daemon asked to restart again")
	}
}

// Before the first signed release exists anywhere, a check is calm, not an
// error.
func TestNoReleaseYetIsNotAnError(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	h := newHarness(t, f, "0.2.6")
	u, _ := url.Parse(httptest.NewServer(http.NotFoundHandler()).URL)
	h.u.env.HTTP = &http.Client{Transport: rewrite{u}}
	st := h.u.Check(context.Background(), true)
	if st.Error != "" || st.State != "idle" || st.Action != "none" || !strings.Contains(st.Reason, "No signed release") {
		t.Fatalf("no release yet: %+v", st)
	}
}
