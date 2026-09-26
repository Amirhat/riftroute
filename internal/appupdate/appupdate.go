// Package appupdate updates the desktop app itself, the way the daemon
// updates itself (internal/updater), and following it: once the daemon runs a
// newer release, the app installs that same release — never ahead of the
// daemon, never backwards, and only in the daemon's update mode (auto:
// download and install on its own; notify: when the user asks; off: never).
//
// The release comes from the manifest the daemon verified, which the app
// verifies again against the compiled-in release keys; the download must
// match the signed SHA-256 and size. The app is replaced as the user who runs
// it (no root), and only where that user may write; the previous app is kept
// beside it. The running app keeps running: the new one starts when the user
// restarts it.
package appupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/update"
)

// States of an app update.
const (
	StateIdle        = "idle"        // up to date, or nothing to do yet
	StateAvailable   = "available"   // notify mode: waiting for the user
	StateDownloading = "downloading" // fetching the release's app
	StateInstalling  = "installing"  // putting it in place
	StateReady       = "ready"       // installed: restart the app to use it
	StateError       = "error"       // the last attempt failed (Error says why)
	StateUnsupported = "unsupported" // this app can't update itself (Why says why)
)

// Status is what the app shows about its own update.
type Status struct {
	State   string `json:"state"`
	Current string `json:"current"`
	// Target is the release being (or already) installed, or offered.
	Target string `json:"target,omitempty"`
	Why    string `json:"why,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Installer puts a verified release artifact in place of the running app.
type Installer interface {
	// Kind is the manifest asset kind it installs ("app-dmg", "app-appimage").
	Kind() string
	// Arch is the manifest asset arch for this machine ("universal" for the
	// macOS app).
	Arch() string
	// Check says why target can't be replaced by this user, or "".
	Check(target string) string
	// Install replaces target with the app in artifact (already checked
	// against the signed hash), which must be release version; the previous
	// app is kept beside it.
	Install(ctx context.Context, artifact, target, version string) error
	// Relaunch starts target once this process has exited.
	Relaunch(target string) error
}

// Env is what the updater needs.
type Env struct {
	Current   string // the app's version (a release version, or a dev label)
	GOOS      string
	Keys      map[string]ed25519.PublicKey
	HTTP      *http.Client
	Target    string // the app to replace: a .app bundle, an AppImage; "" if unknown
	CacheDir  string // downloads go here (created 0700)
	Installer Installer
	Log       *slog.Logger
	Now       func() time.Time
	// OnChange is called with every new status (from the goroutine that
	// changed it).
	OnChange func(Status)
}

// retryAfter paces attempts at a release that failed to download or install.
var retryAfter = time.Hour

// Updater is the app's update state machine. It is driven by the daemon's
// update status (Consider) and by the user (Install, Relaunch).
type Updater struct {
	env Env

	mu     sync.Mutex
	st     Status
	failed map[string]time.Time // release → when an attempt at it last failed
	m      *update.Manifest     // the verified manifest the offer is from
	busy   sync.Mutex
}

// New builds an updater.
func New(env Env) *Updater {
	if env.Log == nil {
		env.Log = slog.Default()
	}
	if env.Now == nil {
		env.Now = time.Now
	}
	if env.Keys == nil {
		env.Keys = update.TrustedKeys
	}
	u := &Updater{env: env, failed: map[string]time.Time{}}
	u.st = Status{State: StateIdle, Current: env.Current}
	if why := u.unsupported(); why != "" {
		u.st.State, u.st.Why = StateUnsupported, why
	}
	return u
}

func (u *Updater) unsupported() string {
	switch {
	case !update.IsRelease(u.env.Current):
		return "this is a development build"
	case u.env.Installer == nil:
		return "the app updates itself on macOS and as an AppImage on Linux; update it the way it was installed"
	case u.env.Target == "":
		return "can't tell where the app is installed"
	}
	return u.env.Installer.Check(u.env.Target)
}

// Status returns the current status.
func (u *Updater) Status() Status {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.st
}

func (u *Updater) set(f func(*Status)) Status {
	u.mu.Lock()
	before := u.st
	f(&u.st)
	st := u.st
	u.mu.Unlock()
	if st != before && u.env.OnChange != nil {
		u.env.OnChange(st)
	}
	return st
}

// Consider looks at the daemon's update status and the manifest it verified
// (raw and sig as signed) and decides: nothing to do, offer the release
// (notify), or install it now (auto). An install runs synchronously; call it
// off the UI's goroutine.
func (u *Updater) Consider(ctx context.Context, daemon domain.UpdateStatus, raw, sig []byte) Status {
	st := u.Status()
	if st.State == StateUnsupported || st.State == StateDownloading || st.State == StateInstalling {
		return st
	}
	m, target, why := u.offer(daemon, raw, sig)
	if target == "" {
		if st.State == StateReady {
			return st // installed; waiting for a restart
		}
		if why != "" {
			u.env.Log.Info("app update: nothing to do", "why", why)
		}
		return u.set(func(s *Status) { s.State, s.Target, s.Error = StateIdle, "", "" })
	}
	if st.State == StateReady && st.Target == target {
		return st
	}
	u.mu.Lock()
	u.m = &m
	u.mu.Unlock()
	if daemon.Mode != domain.UpdateAuto {
		return u.set(func(s *Status) { s.State, s.Target, s.Error = StateAvailable, target, "" })
	}
	if at, ok := u.failedAt(target); ok && u.env.Now().Sub(at) < retryAfter {
		return u.Status() // failed a while ago: the error stays up until the next try
	}
	return u.install(ctx)
}

// offer returns the release the app should move to, from the daemon's
// verified manifest — or "" and why not.
func (u *Updater) offer(daemon domain.UpdateStatus, raw, sig []byte) (update.Manifest, string, string) {
	if daemon.Mode == domain.UpdateOff {
		return update.Manifest{}, "", "updates are off"
	}
	if len(raw) == 0 {
		return update.Manifest{}, "", "no release manifest yet"
	}
	m, err := update.Verify(raw, sig, u.env.Keys)
	if err != nil {
		return update.Manifest{}, "", "the release manifest doesn't verify: " + err.Error()
	}
	switch {
	case !update.Newer(u.env.Current, m.Version):
		return m, "", "up to date"
	case daemon.Current != m.Version:
		// The daemon goes first (it checks the release on this machine and
		// can roll it back); the app follows it there.
		return m, "", "the daemon hasn't moved to " + m.Version + " yet"
	}
	if _, ok := m.Asset(u.env.GOOS, u.env.Installer.Arch(), u.env.Installer.Kind()); !ok {
		return m, "", "the release has no app for this system"
	}
	return m, m.Version, ""
}

// Install installs the offered release now (the user's click in notify mode,
// or a retry).
func (u *Updater) Install(ctx context.Context) (Status, error) {
	u.mu.Lock()
	m := u.m
	st := u.st
	u.mu.Unlock()
	if st.State == StateUnsupported {
		return st, errors.New(st.Why)
	}
	if m == nil || st.Target == "" {
		return st, errors.New("no app update is available")
	}
	st = u.install(ctx)
	if st.State == StateError {
		return st, errors.New(st.Error)
	}
	return st, nil
}

func (u *Updater) install(ctx context.Context) Status {
	if !u.busy.TryLock() {
		return u.Status()
	}
	defer u.busy.Unlock()
	u.mu.Lock()
	m := *u.m
	u.mu.Unlock()
	a, _ := m.Asset(u.env.GOOS, u.env.Installer.Arch(), u.env.Installer.Kind())
	fail := func(err error) Status {
		u.env.Log.Warn("app update failed", "version", m.Version, "err", err)
		u.mu.Lock()
		u.failed[m.Version] = u.env.Now()
		u.mu.Unlock()
		return u.set(func(s *Status) { s.State, s.Target, s.Error = StateError, m.Version, err.Error() })
	}
	u.set(func(s *Status) { s.State, s.Target, s.Error = StateDownloading, m.Version, "" })
	if err := os.MkdirAll(u.env.CacheDir, 0o700); err != nil {
		return fail(err)
	}
	file := filepath.Join(u.env.CacheDir, "RiftRoute-"+m.Version+"."+u.env.Installer.Kind())
	defer os.Remove(file)
	if err := u.download(ctx, a, file); err != nil {
		return fail(err)
	}
	u.set(func(s *Status) { s.State = StateInstalling })
	if err := u.env.Installer.Install(ctx, file, u.env.Target, m.Version); err != nil {
		return fail(err)
	}
	u.env.Log.Info("app update installed; restart the app to use it", "version", m.Version)
	return u.set(func(s *Status) { s.State, s.Target, s.Error = StateReady, m.Version, "" })
}

func (u *Updater) failedAt(version string) (time.Time, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	t, ok := u.failed[version]
	return t, ok
}

// download fetches a release asset to dst and checks it against the signed
// size and SHA-256.
func (u *Updater) download(ctx context.Context, a update.ManifestAsset, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return err
	}
	resp, err := u.env.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: %s", resp.Status)
	}
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
	if hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return errors.New("download doesn't match the signed checksum")
	}
	return nil
}

// Relaunch starts the installed app once this process exits; the caller
// then quits.
func (u *Updater) Relaunch() error {
	if st := u.Status(); st.State != StateReady {
		return errors.New("no app update is waiting for a restart")
	}
	return u.env.Installer.Relaunch(u.env.Target)
}
