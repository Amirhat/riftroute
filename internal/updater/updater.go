// Package updater keeps riftrouted up to date (phase 2). It fetches the
// signed release manifest (our server first, GitHub Releases as fallback),
// decides with update.Decide, and — when allowed — downloads the daemon,
// verifies it against the signed hash, self-tests it on a copy of the
// database, waits for a quiet moment and swaps it in. The service manager
// restarts the daemon; BootGuard (boot.go) rolls back on its own, without any
// network, if the new version doesn't come up healthy.
//
// Only the installed daemon binary is ever replaced. The desktop app and
// package-managed installs are notified, never modified.
package updater

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/update"
)

// Defaults for the production endpoints.
const (
	DefaultServerURL   = "https://riftroute.tellnew.tech/api/v1/update/"
	DefaultFallbackURL = "https://github.com/Amirhat/riftroute/releases/latest/download/"
)

// RestartExitCode is how the daemon exits to be restarted into a new or
// restored binary: non-zero so systemd's Restart=on-failure restarts it
// (launchd's KeepAlive restarts on any exit).
const RestartExitCode = 75

// Timing of the automatic loop.
var (
	firstCheck  = 10 * time.Minute
	checkEvery  = 6 * time.Hour
	checkJitter = 30 * time.Minute
	idleQuiet   = 10 * time.Minute // no transaction for this long
	idlePoll    = time.Minute
)

// Env is everything the updater needs from the daemon; the zero values of
// the function fields are never called.
type Env struct {
	Current     string // running version
	Channel     string
	ServerURL   string
	FallbackURL string
	Keys        map[string]ed25519.PublicKey
	GOOS        string
	GOARCH      string

	Binary   string // the installed daemon binary this process runs
	StateDir string // marker, status, staging, database backup
	DBPath   string

	// SelfUpdatable is false where files must not be replaced (package-managed
	// install, a daemon not running as the installed service).
	SelfUpdatable bool
	// Loop runs the automatic checks (false: on demand only, e.g. dev/fake).
	Loop bool

	HTTP *http.Client
	Mode func() domain.UpdateMode
	// Idle reports whether it's a quiet moment to restart the daemon, and why
	// not when it isn't.
	Idle func() (bool, string)
	// BackupDB writes a consistent copy of the live database to path.
	BackupDB func(path string) error
	// SelfTest runs a staged binary against a database copy.
	SelfTest func(ctx context.Context, bin, db string) error
	// Restart ends the daemon gracefully with RestartExitCode.
	Restart func()
	Log     *slog.Logger
	Now     func() time.Time
}

// Updater is the daemon's update state machine.
type Updater struct {
	env Env

	mu       sync.Mutex
	st       domain.UpdateStatus
	ps       persisted
	manifest *update.Manifest // last verified manifest
	staged   *staged
	wantNow  bool // the user asked to install; ignore the mode for the staged one
	kick     chan struct{}
	busy     sync.Mutex // one check/stage/install at a time
}

type staged struct {
	version string
	path    string
}

// persisted survives restarts and database restores (a file in StateDir).
type persisted struct {
	Bucket         int       `json:"bucket"`
	Skip           string    `json:"skip,omitempty"`
	RolledBackFrom string    `json:"rolled_back_from,omitempty"`
	InstalledAt    time.Time `json:"installed_at,omitempty"`
	LastCheck      time.Time `json:"last_check,omitempty"`
}

func statePath(dir string) string   { return filepath.Join(dir, "update-state.json") }
func stagingDir(dir string) string  { return filepath.Join(dir, "update-staging") }
func backupPath(dir string) string  { return filepath.Join(dir, "update-backup.db") }
func prevBinary(bin string) string  { return bin + ".prev" }
func pendingPath(dir string) string { return filepath.Join(dir, "update-pending.json") }

// New loads (or creates) the persisted state. The rollout bucket is a random
// 0–99 chosen once per install; it never leaves this computer.
func New(env Env) (*Updater, error) {
	if env.Now == nil {
		env.Now = time.Now
	}
	if env.Log == nil {
		env.Log = slog.Default()
	}
	if env.HTTP == nil {
		env.HTTP = NewHTTPClient()
	}
	if env.Keys == nil {
		env.Keys = update.TrustedKeys
	}
	u := &Updater{env: env, kick: make(chan struct{}, 1)}
	ps, err := loadPersisted(env.StateDir)
	if err != nil {
		return nil, err
	}
	u.ps = ps
	u.st = domain.UpdateStatus{
		Current: env.Current, State: "idle", LastCheck: ps.LastCheck,
		RolledBackFrom: ps.RolledBackFrom, InstalledAt: ps.InstalledAt, SelfUpdatable: env.SelfUpdatable,
	}
	return u, nil
}

func loadPersisted(dir string) (persisted, error) {
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
		return ps, savePersisted(dir, ps)
	default:
		return ps, err
	}
}

func savePersisted(dir string, ps persisted) error {
	b, _ := json.MarshalIndent(ps, "", "  ")
	return writeFileAtomic(statePath(dir), b, 0o600)
}

// Status is a snapshot for the API and State.
func (u *Updater) Status() domain.UpdateStatus {
	u.mu.Lock()
	defer u.mu.Unlock()
	st := u.st
	if u.env.Mode != nil {
		st.Mode = u.env.Mode()
	}
	_, err := os.Stat(prevBinary(u.env.Binary))
	st.CanRollBack = u.env.SelfUpdatable && err == nil
	return st
}

func (u *Updater) set(f func(*domain.UpdateStatus)) {
	u.mu.Lock()
	f(&u.st)
	u.mu.Unlock()
}

// Run is the automatic loop: a first check a while after start, then every
// few hours; a staged update is installed at the first quiet moment.
func (u *Updater) Run(ctx context.Context) {
	if !u.env.Loop {
		return
	}
	next := time.NewTimer(firstCheck)
	defer next.Stop()
	idle := time.NewTicker(idlePoll)
	defer idle.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-next.C:
			if u.env.Mode() != domain.UpdateOff {
				u.Check(ctx, false)
			}
			next.Reset(checkEvery + jitter(checkJitter))
		case <-u.kick:
		case <-idle.C:
		}
		u.maybeInstall(ctx)
	}
}

func jitter(d time.Duration) time.Duration {
	var n [8]byte
	_, _ = rand.Read(n[:])
	return time.Duration(binary.BigEndian.Uint64(n[:])%uint64(2*d)) - d
}

// Check fetches and verifies the manifest and decides; a decision to install
// stages the update (download, verify, self-test). manual checks report
// availability even when automatic updates are off.
func (u *Updater) Check(ctx context.Context, manual bool) domain.UpdateStatus {
	u.busy.Lock()
	defer u.busy.Unlock()
	mode := u.env.Mode()
	decideMode := string(mode)
	if manual && mode == domain.UpdateOff {
		decideMode = string(domain.UpdateNotify)
	}
	u.set(func(s *domain.UpdateStatus) { s.State, s.Error = "checking", "" })
	m, adv, src, err := u.fetch(ctx)
	now := u.env.Now()
	u.mu.Lock()
	u.ps.LastCheck = now
	_ = savePersisted(u.env.StateDir, u.ps)
	u.mu.Unlock()
	if err != nil {
		u.env.Log.Warn("update check failed", "err", err)
		u.set(func(s *domain.UpdateStatus) { s.State, s.Error, s.LastCheck = "error", err.Error(), now })
		return u.Status()
	}
	u.mu.Lock()
	skip := u.ps.Skip
	u.manifest = &m
	u.mu.Unlock()
	d := update.Decide(update.DecideInput{
		Current: u.env.Current, Mode: decideMode, Manifest: m, Advice: adv, Bucket: u.bucket(),
		GOOS: u.env.GOOS, GOARCH: u.env.GOARCH, SelfUpdatable: u.env.SelfUpdatable, Skip: skip,
	})
	u.set(func(s *domain.UpdateStatus) {
		s.State, s.LastCheck, s.Latest, s.Source = "idle", now, m.Version, src
		s.Action, s.Reason, s.NotesURL = string(d.Action), d.Reason, m.NotesURL
	})
	u.env.Log.Info("update check", "latest", m.Version, "source", src, "action", d.Action, "reason", d.Reason)
	if d.Action == update.ActionInstall {
		u.stage(ctx, m)
	}
	return u.Status()
}

func (u *Updater) bucket() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.ps.Bucket
}

// InstallNow is the user's "Install now" (notify mode): stage if needed, then
// install at the first quiet moment regardless of the mode. It never goes
// past a halt, a rolled-back version or a non-updatable install.
func (u *Updater) InstallNow(ctx context.Context) (domain.UpdateStatus, error) {
	if !u.env.SelfUpdatable {
		return u.Status(), errors.New("this install is managed elsewhere; update it the way you installed it")
	}
	if !update.IsRelease(u.env.Current) {
		return u.Status(), errors.New("this is a development build; install the release yourself")
	}
	u.mu.Lock()
	haveStaged := u.staged != nil
	u.mu.Unlock()
	if !haveStaged {
		u.busy.Lock()
		m, adv, _, err := u.fetch(ctx)
		if err != nil {
			u.busy.Unlock()
			return u.Status(), err
		}
		u.mu.Lock()
		skip := u.ps.Skip
		u.mu.Unlock()
		// The user asked: the rollout percent doesn't apply, a halt does.
		if adv != nil {
			adv = &update.Advice{RolloutPercent: 100, Halt: adv.Halt}
		}
		d := update.Decide(update.DecideInput{Current: u.env.Current, Mode: "auto", Manifest: m, Advice: adv, Bucket: 0,
			GOOS: u.env.GOOS, GOARCH: u.env.GOARCH, SelfUpdatable: true, Skip: skip})
		if d.Action != update.ActionInstall {
			u.busy.Unlock()
			return u.Status(), errors.New(d.Reason)
		}
		u.stage(ctx, m)
		u.busy.Unlock()
	}
	u.mu.Lock()
	ok := u.staged != nil
	if ok {
		u.wantNow = true
	}
	u.mu.Unlock()
	if !ok {
		st := u.Status()
		return st, errors.New(st.Error)
	}
	select {
	case u.kick <- struct{}{}:
	default:
	}
	u.maybeInstall(ctx)
	return u.Status(), nil
}

// ---------------------------------------------------------------- fetching

type serverResponse struct {
	Manifest  string        `json:"manifest"`
	Signature string        `json:"signature"`
	Advice    update.Advice `json:"advice"`
}

// fetch returns a verified manifest: our server first (with its advice),
// GitHub Releases if that fails. A manifest that doesn't verify is an error,
// wherever it came from.
func (u *Updater) fetch(ctx context.Context) (update.Manifest, *update.Advice, string, error) {
	m, adv, err := u.fromServer(ctx)
	if err == nil {
		return m, adv, "server", nil
	}
	u.env.Log.Info("update server unavailable; trying GitHub", "err", err)
	m2, err2 := u.fromGitHub(ctx)
	if err2 != nil {
		return update.Manifest{}, nil, "", fmt.Errorf("update server: %v; GitHub: %v", err, err2)
	}
	return m2, nil, "github", nil
}

func (u *Updater) fromServer(ctx context.Context) (update.Manifest, *update.Advice, error) {
	b, err := u.get(ctx, u.env.ServerURL+u.env.Channel, 1<<20)
	if err != nil {
		return update.Manifest{}, nil, err
	}
	var r serverResponse
	if err := json.Unmarshal(b, &r); err != nil {
		return update.Manifest{}, nil, fmt.Errorf("server response: %w", err)
	}
	raw, err1 := base64.StdEncoding.DecodeString(r.Manifest)
	sig, err2 := base64.StdEncoding.DecodeString(r.Signature)
	if err1 != nil || err2 != nil {
		return update.Manifest{}, nil, errors.New("server response: bad encoding")
	}
	m, err := u.verify(raw, sig)
	if err != nil {
		return update.Manifest{}, nil, err
	}
	adv := r.Advice
	return m, &adv, nil
}

func (u *Updater) fromGitHub(ctx context.Context) (update.Manifest, error) {
	raw, err := u.get(ctx, u.env.FallbackURL+"manifest.json", 1<<20)
	if err != nil {
		return update.Manifest{}, err
	}
	sig, err := u.get(ctx, u.env.FallbackURL+"manifest.json.sig", 64<<10)
	if err != nil {
		return update.Manifest{}, err
	}
	return u.verify(raw, sig)
}

func (u *Updater) verify(raw, sig []byte) (update.Manifest, error) {
	m, err := update.Verify(raw, sig, u.env.Keys)
	if err != nil {
		return m, err
	}
	if m.Channel != u.env.Channel {
		return m, fmt.Errorf("manifest is for channel %q, not %q", m.Channel, u.env.Channel)
	}
	return m, nil
}

// NewHTTPClient only ever talks HTTPS to the allow-listed hosts — every
// redirect hop included — and sends nothing that identifies the install.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if !update.AllowedAssetURL(req.URL.String()) {
				return fmt.Errorf("redirect to %s not allowed", req.URL.Host)
			}
			return nil
		},
	}
}

func (u *Updater) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	resp, err := u.open(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: response too large", url)
	}
	return b, nil
}

func (u *Updater) open(ctx context.Context, url string) (*http.Response, error) {
	if !update.AllowedAssetURL(url) {
		return nil, fmt.Errorf("%s: not an allowed update URL", url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "riftroute")
	resp, err := u.env.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return resp, nil
}

// ---------------------------------------------------------------- staging

// stage downloads the release tarball, checks it against the signed hash
// and size, unpacks the daemon, and self-tests it. A release that fails its
// self-test here is skipped (never retried) until a newer one appears.
func (u *Updater) stage(ctx context.Context, m update.Manifest) {
	u.mu.Lock()
	if u.staged != nil && u.staged.version == m.Version {
		u.mu.Unlock()
		return
	}
	u.mu.Unlock()
	a, ok := m.Asset(u.env.GOOS, u.env.GOARCH, "tarball")
	if !ok {
		return
	}
	fail := func(skip bool, err error) {
		u.env.Log.Warn("update staging failed", "version", m.Version, "err", err)
		u.set(func(s *domain.UpdateStatus) { s.State, s.Error = "error", fmt.Sprintf("%s: %v", m.Version, err) })
		if skip {
			u.mu.Lock()
			u.ps.Skip = m.Version
			_ = savePersisted(u.env.StateDir, u.ps)
			u.mu.Unlock()
		}
	}
	dir := stagingDir(u.env.StateDir)
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fail(false, err)
		return
	}
	u.set(func(s *domain.UpdateStatus) { s.State = "downloading" })
	tgz := filepath.Join(dir, "release.tar.gz")
	if err := u.download(ctx, a, tgz); err != nil {
		fail(false, err) // network trouble: try again next time
		return
	}
	bin := filepath.Join(dir, "riftrouted")
	if err := extractDaemon(tgz, bin); err != nil {
		fail(true, err)
		return
	}
	_ = os.Remove(tgz)
	if err := u.selfTest(ctx, bin, m.Version); err != nil {
		fail(true, fmt.Errorf("self-test failed: %w", err))
		return
	}
	u.mu.Lock()
	u.staged = &staged{version: m.Version, path: bin}
	u.mu.Unlock()
	u.set(func(s *domain.UpdateStatus) { s.State, s.Staged, s.Error = "waiting", m.Version, "" })
	u.env.Log.Info("update staged", "version", m.Version)
}

func (u *Updater) download(ctx context.Context, a update.ManifestAsset, dst string) error {
	resp, err := u.open(ctx, a.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, a.Size+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != a.Size {
		return fmt.Errorf("download is %d bytes, the signed manifest says %d", n, a.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != a.SHA256 {
		return errors.New("download doesn't match the signed checksum")
	}
	return nil
}

// extractDaemon pulls the one file it needs — riftrouted — out of the
// release tarball, refusing anything that isn't a plain file of sane size.
func extractDaemon(tgz, dst string) error {
	f, err := os.Open(tgz)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return errors.New("release has no riftrouted")
		}
		if err != nil {
			return err
		}
		if strings.TrimPrefix(h.Name, "./") != "riftrouted" {
			continue
		}
		if h.Typeflag != tar.TypeReg || h.Size <= 0 || h.Size > 150<<20 {
			return errors.New("riftrouted in the release is not a plain file")
		}
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, io.LimitReader(tr, h.Size)); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	}
}

// selfTest runs the staged binary: its version must be the manifest's, and
// it must open a copy of the live database (running its migrations there)
// and initialise its provider without error.
func (u *Updater) selfTest(ctx context.Context, bin, version string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-version").Output()
	if err != nil {
		return fmt.Errorf("%s -version: %w", filepath.Base(bin), err)
	}
	if got := strings.Fields(string(out)); len(got) == 0 || strings.TrimPrefix(got[0], "v") != version {
		return fmt.Errorf("the binary says it is %q, the manifest says %s", strings.TrimSpace(string(out)), version)
	}
	if u.env.SelfTest == nil {
		return nil
	}
	db := filepath.Join(stagingDir(u.env.StateDir), "selftest.db")
	_ = os.Remove(db)
	defer os.Remove(db)
	if err := u.env.BackupDB(db); err != nil {
		return fmt.Errorf("copy database: %w", err)
	}
	return u.env.SelfTest(ctx, bin, db)
}

// ---------------------------------------------------------------- install

// maybeInstall swaps in a staged update when the mode (or the user) allows
// it and the daemon is quiet.
func (u *Updater) maybeInstall(ctx context.Context) {
	u.mu.Lock()
	s, want := u.staged, u.wantNow
	u.mu.Unlock()
	if s == nil || !u.env.SelfUpdatable {
		return
	}
	if !want && u.env.Mode() != domain.UpdateAuto {
		return
	}
	if ok, why := u.env.Idle(); !ok {
		u.set(func(st *domain.UpdateStatus) {
			st.State, st.Reason = "waiting", fmt.Sprintf("%s is ready; installing at a quiet moment (%s)", s.version, why)
		})
		return
	}
	if !u.busy.TryLock() {
		return
	}
	defer u.busy.Unlock()
	if err := u.swap(s); err != nil {
		u.env.Log.Error("update install failed", "version", s.version, "err", err)
		u.set(func(st *domain.UpdateStatus) { st.State, st.Error = "error", "install failed: "+err.Error() })
		return
	}
	u.env.Log.Info("update installed; restarting into it", "from", u.env.Current, "to", s.version)
	u.set(func(st *domain.UpdateStatus) { st.State = "installing" })
	u.env.Restart()
}

// swap backs up the database and the current binary, puts the new binary in
// place atomically, and leaves the marker BootGuard reads on the next start.
func (u *Updater) swap(s *staged) error {
	dir := u.env.StateDir
	_ = os.Remove(backupPath(dir))
	if err := u.env.BackupDB(backupPath(dir)); err != nil {
		return fmt.Errorf("back up database: %w", err)
	}
	if err := copyFileAtomic(u.env.Binary, prevBinary(u.env.Binary), 0o755); err != nil {
		return fmt.Errorf("keep current binary: %w", err)
	}
	mk := marker{From: u.env.Current, To: s.version, At: u.env.Now()}
	if err := writeMarker(dir, mk); err != nil {
		return err
	}
	if err := copyFileAtomic(s.path, u.env.Binary, 0o755); err != nil {
		_ = os.Remove(pendingPath(dir))
		return fmt.Errorf("install binary: %w", err)
	}
	_ = os.RemoveAll(stagingDir(dir))
	return nil
}

// RequestRollback asks for the previous binary back: the restore itself runs
// in BootGuard on the next start (the database can't be replaced while it's
// open), then the daemon restarts into the old version.
func (u *Updater) RequestRollback() error {
	if !u.env.SelfUpdatable {
		return errors.New("this install is managed elsewhere")
	}
	if _, err := os.Stat(prevBinary(u.env.Binary)); err != nil {
		return errors.New("no previous version is kept on this computer")
	}
	if err := writeMarker(u.env.StateDir, marker{From: u.env.Current, To: u.env.Current, At: u.env.Now(), Rollback: true}); err != nil {
		return err
	}
	u.env.Log.Warn("rollback requested by the user", "from", u.env.Current)
	u.env.Restart()
	return nil
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
	return os.Rename(tmp.Name(), path)
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
