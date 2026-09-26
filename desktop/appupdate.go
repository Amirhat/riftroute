package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/Amirhat/riftroute/internal/appupdate"
	"github.com/Amirhat/riftroute/internal/buildinfo"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/updater"
)

// The app updates itself after the daemon (internal/appupdate): each state
// push carries the daemon's update status, and once the daemon runs a newer
// release than this app, the app installs that same release — in the
// daemon's update mode.

type appUpdates struct {
	u *appupdate.Updater

	mu      sync.Mutex
	key     string    // the daemon's version and mode, last considered
	at      time.Time // when
	running bool
}

// reconsiderEvery re-checks with nothing changed (a failed download is
// retried then, once its backoff allows).
const reconsiderEvery = 30 * time.Minute

func (a *App) initAppUpdates() {
	exe, _ := os.Executable()
	cache, err := os.UserCacheDir()
	if err != nil {
		cache = os.TempDir()
	}
	// The daemon's client, minus its overall timeout: the app is ~30 MB and
	// the install's own deadline bounds it.
	hc := updater.NewHTTPClient()
	hc.Timeout = 0
	a.appUpd = &appUpdates{u: appupdate.New(appupdate.Env{
		Current:   buildinfo.Label(buildinfo.Current(version)),
		GOOS:      runtime.GOOS,
		HTTP:      hc,
		Target:    appupdate.Target(exe),
		CacheDir:  filepath.Join(cache, "RiftRoute", "update"),
		Installer: appupdate.NewInstaller(),
		OnChange:  func(st appupdate.Status) { a.emit("rr:app-update", st) },
	})}
}

// considerAppUpdate runs on each state push. The work — asking the daemon
// for the manifest it verified, maybe installing — runs on its own
// goroutine, one at a time, and only when the daemon's version or mode
// changed or reconsiderEvery passed.
func (a *App) considerAppUpdate(d *domain.UpdateStatus) {
	au := a.appUpd
	if d == nil || au == nil || a.ctx == nil {
		return
	}
	key := d.Current + "|" + string(d.Mode) + "|" + d.Latest + "|" + d.RolledBackFrom
	if d.Probation {
		key += "|probation"
	}
	au.mu.Lock()
	if au.running || (key == au.key && time.Since(au.at) < reconsiderEvery) {
		au.mu.Unlock()
		return
	}
	au.key, au.at, au.running = key, time.Now(), true
	au.mu.Unlock()
	daemon := *d
	go func() {
		defer func() {
			au.mu.Lock()
			au.running = false
			au.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(a.ctx, time.Hour)
		defer cancel()
		raw, sig, err := a.client.UpdateManifest(ctx)
		if err != nil {
			raw, sig = nil, nil // none yet (or an older daemon): nothing to offer
		}
		au.u.Consider(ctx, daemon, raw, sig)
	}()
}

// GetAppUpdate returns the app's own update status.
func (a *App) GetAppUpdate() appupdate.Status {
	if a.appUpd == nil {
		return appupdate.Status{State: appupdate.StateUnsupported, Current: version}
	}
	return a.appUpd.u.Status()
}

// InstallAppUpdate installs the offered app update now (notify mode). It
// downloads the release's app, so it can take a few minutes.
func (a *App) InstallAppUpdate() (appupdate.Status, error) {
	ctx, cancel := context.WithTimeout(a.ctx, time.Hour)
	defer cancel()
	return a.appUpd.u.Install(ctx)
}

// RestartApp quits and starts the updated app.
func (a *App) RestartApp() error {
	if err := a.appUpd.u.Relaunch(); err != nil {
		return err
	}
	wruntime.Quit(a.ctx)
	return nil
}
