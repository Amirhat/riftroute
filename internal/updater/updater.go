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
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
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

// Timing.
var (
	firstCheck  = 10 * time.Minute
	checkEvery  = 6 * time.Hour
	checkJitter = 30 * time.Minute
	idlePoll    = time.Minute      // how often a staged update looks for a quiet moment
	decideWait  = 10 * time.Second // how long a "check now" waits for the verdict
)

// Env is everything the updater needs from the daemon.
type Env struct {
	Ctx         context.Context // the daemon's lifetime; jobs run on it, not on a request's
	Current     string          // running version
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
	// Quiesce takes the daemon's apply lock if it's a quiet moment and holds
	// it until release (from the swap until the process exits); otherwise it
	// says why not.
	Quiesce func() (release func(), ok bool, why string)
	// BackupDB writes a consistent copy of the live database to path.
	BackupDB func(path string) error
	// SelfTest runs a staged binary against a database copy, with the service's
	// own arguments.
	SelfTest func(ctx context.Context, bin, db string) error
	// Restart ends the daemon gracefully with RestartExitCode.
	Restart func()
	Log     *slog.Logger
	Now     func() time.Time
}

// Updater is the daemon's update state machine.
type Updater struct {
	env Env

	mu         sync.Mutex
	st         domain.UpdateStatus
	ps         persisted // cached; refreshed from disk on every write and by Reload
	staged     *staged
	wantNow    bool // the user asked to install: the mode doesn't apply to it
	installing bool // swapped (or rolling back): nothing more until we exit
	kick       chan struct{}
	busy       sync.Mutex // one check/stage/install at a time
	jobs       sync.WaitGroup
}

type jobKind int

const (
	jobAuto    jobKind = iota // the periodic check
	jobManual                 // "check now": reports even when updates are off
	jobInstall                // "install now": rollout doesn't apply, a halt does
)

// New loads (or creates) the persisted state. The rollout bucket is a random
// 0–99 chosen once per install; it never leaves this computer.
func New(env Env) (*Updater, error) {
	if env.Ctx == nil {
		env.Ctx = context.Background()
	}
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
	ps, err := loadPersisted(env.StateDir)
	if err != nil {
		return nil, err
	}
	u := &Updater{env: env, ps: ps, kick: make(chan struct{}, 1)}
	u.st = domain.UpdateStatus{Current: env.Current, State: "idle", LastCheck: ps.LastCheck, SelfUpdatable: env.SelfUpdatable}
	return u, nil
}

// Reload re-reads the state file (after the boot guard confirmed an update).
func (u *Updater) Reload() {
	if ps, err := loadPersisted(u.env.StateDir); err == nil {
		u.mu.Lock()
		u.ps = ps
		u.mu.Unlock()
	}
}

func (u *Updater) save(f func(*persisted)) {
	ps, err := updateState(u.env.StateDir, f)
	if err != nil {
		u.env.Log.Warn("update state not saved", "err", err)
		return
	}
	u.mu.Lock()
	u.ps = ps
	u.mu.Unlock()
}

// Status is a snapshot for the API and State.
func (u *Updater) Status() domain.UpdateStatus {
	u.mu.Lock()
	defer u.mu.Unlock()
	st := u.st
	st.Mode = u.env.Mode()
	st.RolledBackFrom, st.RolledBackBy, st.InstalledAt = u.ps.RolledBackFrom, u.ps.RolledBackBy, u.ps.InstalledAt
	if st.Error == "" && u.ps.RollbackError != "" {
		st.Error = "rolling back failed: " + u.ps.RollbackError
	}
	st.CanRollBack = u.env.SelfUpdatable && fileExists(prevBinary(u.env.Binary)) && !u.installing
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
				u.runJob(ctx, jobAuto, nil)
			}
			next.Reset(checkEvery + jitter(checkJitter))
			continue
		case <-u.kick:
		case <-idle.C:
		}
		if ctx.Err() == nil && u.busy.TryLock() {
			u.installLocked(ctx)
			u.busy.Unlock()
		}
	}
}

func jitter(d time.Duration) time.Duration {
	var n [8]byte
	_, _ = rand.Read(n[:])
	return time.Duration(binary.BigEndian.Uint64(n[:])%uint64(2*d)) - d
}

// CheckNow is "Check now": it runs on the daemon's lifetime (a slow download
// or self-test isn't cut short by the caller hanging up), and returns once
// the verdict is known — or after a few seconds with the work still going.
func (u *Updater) CheckNow() domain.UpdateStatus { return u.startJob(jobManual) }

// InstallNow is the user's "Install now": the same check, with the rollout
// percent waived (a halt still applies), then the install at the first quiet
// moment regardless of the mode.
func (u *Updater) InstallNow() (domain.UpdateStatus, error) {
	if !u.env.SelfUpdatable {
		return u.Status(), errors.New("this install is managed elsewhere; update it the way you installed it")
	}
	if !update.IsRelease(u.env.Current) {
		return u.Status(), errors.New("this is a development build; install the release yourself")
	}
	u.mu.Lock()
	u.wantNow = true
	u.mu.Unlock()
	return u.startJob(jobInstall), nil
}

func (u *Updater) startJob(kind jobKind) domain.UpdateStatus {
	decided := make(chan struct{})
	u.jobs.Add(1)
	go func() {
		defer u.jobs.Done()
		u.runJob(u.env.Ctx, kind, decided)
	}()
	select {
	case <-decided:
	case <-time.After(decideWait):
	case <-u.env.Ctx.Done():
	}
	return u.Status()
}

// wait blocks until background jobs finish (tests).
func (u *Updater) wait() { u.jobs.Wait() }

func (u *Updater) runJob(ctx context.Context, kind jobKind, decided chan struct{}) {
	u.busy.Lock()
	defer u.busy.Unlock()
	u.job(ctx, kind, decided)
}

// job: fetch, decide, then stage and (maybe) install. Holds u.busy.
func (u *Updater) job(ctx context.Context, kind jobKind, decided chan struct{}) {
	var once sync.Once
	signal := func() {
		if decided != nil {
			once.Do(func() { close(decided) })
		}
	}
	defer signal()
	if ctx.Err() != nil {
		return
	}
	u.set(func(s *domain.UpdateStatus) { s.State, s.Error = "checking", "" })
	f, err := u.fetch(ctx)
	now := u.env.Now()
	u.save(func(ps *persisted) { ps.LastCheck = now })
	u.set(func(s *domain.UpdateStatus) { s.LastCheck = now })
	switch {
	case errors.Is(err, errNoRelease):
		u.set(func(s *domain.UpdateStatus) {
			s.State, s.Action, s.Reason, s.Latest, s.Source = "idle", string(update.ActionNone), "No signed release has been published yet.", "", ""
		})
		u.dropStaged()
		u.clearWant()
		return
	case err != nil:
		u.env.Log.Warn("update check failed", "err", err)
		u.set(func(s *domain.UpdateStatus) { s.State, s.Error = "error", err.Error() })
		return
	}
	d := u.decide(f, kind)
	u.set(func(s *domain.UpdateStatus) {
		s.State, s.Latest, s.Source = "idle", f.m.Version, f.source
		s.Action, s.Reason, s.NotesURL = string(d.Action), d.Reason, f.m.NotesURL
	})
	u.env.Log.Info("update check", "latest", f.m.Version, "source", f.source, "action", d.Action, "reason", d.Reason)
	signal()
	if d.Action != update.ActionInstall {
		// Whatever was staged is no longer wanted (a halt, a rollout cut
		// back, the mode changed): never install it.
		u.dropStaged()
		u.clearWant()
		return
	}
	if u.stage(ctx, f.m) {
		u.installLocked(ctx)
	}
}

func (u *Updater) clearWant() {
	u.mu.Lock()
	u.wantNow = false
	u.mu.Unlock()
}

// decide applies update.Decide with the job's rules.
func (u *Updater) decide(f fetched, kind jobKind) update.Decision {
	u.mu.Lock()
	ps, want := u.ps, u.wantNow
	u.mu.Unlock()
	in := update.DecideInput{
		Current: u.env.Current, Mode: string(u.env.Mode()), Manifest: f.m, Advice: f.advice, Bucket: ps.Bucket,
		GOOS: u.env.GOOS, GOARCH: u.env.GOARCH, SelfUpdatable: u.env.SelfUpdatable, Skip: ps.Skip,
	}
	if kind == jobManual && in.Mode == string(domain.UpdateOff) {
		in.Mode = string(domain.UpdateNotify)
	}
	if kind == jobInstall || want {
		in.Mode, in.Bucket = string(domain.UpdateAuto), 0
		if f.advice != nil {
			in.Advice = &update.Advice{RolloutPercent: 100, Halt: f.advice.Halt}
		}
	}
	d := update.Decide(in)
	if d.Action == update.ActionInstall && f.hold != "" {
		return update.Decision{Action: update.ActionHold, Reason: f.hold}
	}
	return d
}

// installLocked swaps in a staged update when the mode (or the user) allows
// it and the daemon is quiet — after one last look at the release's status,
// so a halt since staging stops it here. Holds u.busy.
func (u *Updater) installLocked(ctx context.Context) {
	if ctx.Err() != nil || !u.env.SelfUpdatable {
		return
	}
	u.mu.Lock()
	s, want, installing := u.staged, u.wantNow, u.installing
	u.mu.Unlock()
	if installing || s == nil {
		return
	}
	mode := u.env.Mode()
	if mode == domain.UpdateOff {
		u.clearWant()
		want = false
	}
	if !want && mode != domain.UpdateAuto {
		return
	}
	release, ok, why := u.env.Quiesce()
	if !ok {
		u.set(func(st *domain.UpdateStatus) {
			st.State, st.Reason = "waiting", fmt.Sprintf("%s is ready; installing at a quiet moment (%s)", s.version, why)
		})
		return
	}
	if !u.stillWanted(ctx, s.version) {
		release()
		return
	}
	if sum, err := fileSHA256(s.path); err != nil || sum != s.sum {
		u.dropStaged()
		release()
		u.set(func(st *domain.UpdateStatus) {
			st.State, st.Error = "error", "the staged update changed on disk; it will be downloaded again"
		})
		return
	}
	if err := u.swap(s); err != nil {
		release()
		u.env.Log.Error("update install failed", "version", s.version, "err", err)
		u.set(func(st *domain.UpdateStatus) { st.State, st.Error = "error", "install failed: "+err.Error() })
		return
	}
	u.mu.Lock()
	u.installing, u.staged, u.wantNow = true, nil, false
	u.mu.Unlock()
	u.env.Log.Info("update installed; restarting into it", "from", u.env.Current, "to", s.version)
	u.set(func(st *domain.UpdateStatus) { st.State, st.Staged = "installing", s.version })
	// The apply lock stays held: no change may start before the restart.
	u.env.Restart()
}

// stillWanted re-checks the staged version just before the swap. When
// neither source can be reached it goes by the server's last word.
func (u *Updater) stillWanted(ctx context.Context, version string) bool {
	tctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	f, err := u.fetch(tctx)
	if err != nil {
		u.mu.Lock()
		la := u.ps.LastAdvice
		u.mu.Unlock()
		if la.Version == version && la.Halt {
			u.dropStaged()
			u.set(func(st *domain.UpdateStatus) {
				st.State, st.Action, st.Reason = "idle", string(update.ActionHold), "the rollout of "+version+" is paused"
			})
			return false
		}
		return true
	}
	d := u.decide(f, jobAuto)
	if f.m.Version != version || d.Action != update.ActionInstall {
		u.dropStaged()
		u.set(func(st *domain.UpdateStatus) {
			st.State, st.Latest, st.Action, st.Reason = "idle", f.m.Version, string(d.Action), d.Reason
		})
		return false
	}
	return true
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
	if err := writeMarker(dir, marker{From: u.env.Current, To: s.version, At: u.env.Now()}); err != nil {
		return err
	}
	if err := copyFileAtomic(s.path, u.env.Binary, 0o755); err != nil {
		_ = os.Remove(pendingPath(dir))
		return fmt.Errorf("install binary: %w", err)
	}
	_ = os.RemoveAll(stagingDir(dir))
	return nil
}

// RequestRollback asks for the previous binary back. It waits for a quiet
// moment like an install does; the restore itself runs in BootGuard on the
// next start (the database can't be replaced while it's open).
func (u *Updater) RequestRollback() error {
	if !u.env.SelfUpdatable {
		return errors.New("this install is managed elsewhere")
	}
	if !fileExists(prevBinary(u.env.Binary)) {
		return errors.New("no previous version is kept on this computer")
	}
	u.busy.Lock()
	defer u.busy.Unlock()
	u.mu.Lock()
	installing := u.installing
	u.mu.Unlock()
	if installing {
		return errors.New("the daemon is already restarting")
	}
	release, ok, why := u.env.Quiesce()
	if !ok {
		return fmt.Errorf("not right now: %s — try again in a moment", why)
	}
	if err := writeMarker(u.env.StateDir, marker{From: u.env.Current, To: u.env.Current, At: u.env.Now(), Rollback: true}); err != nil {
		release()
		return err
	}
	u.mu.Lock()
	u.installing = true
	u.mu.Unlock()
	u.dropStaged()
	u.env.Log.Warn("rollback requested by the user", "from", u.env.Current)
	u.env.Restart()
	return nil
}
