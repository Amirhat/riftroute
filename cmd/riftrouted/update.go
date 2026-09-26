package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Amirhat/riftroute/internal/buildinfo"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/platform"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/store"
	"github.com/Amirhat/riftroute/internal/updater"
)

// restartExit ends run() so main exits with a code the service manager
// restarts on (into a new, or restored, binary).
type restartExit int

func (e restartExit) Error() string { return fmt.Sprintf("restarting (exit %d)", int(e)) }

// executable is this process's binary, symlinks resolved.
func executable() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		return p
	}
	return exe
}

// selfUpdatable: only the root daemon running as the installed service may
// replace its own binary, and never one a package manager owns.
func selfUpdatable(exe, providerName string) bool {
	if providerName == "fake" || !platform.IsPrivileged() || exe != platform.InstalledDaemonPath() {
		return false
	}
	return !packageManaged(exe)
}

// packageManaged reports whether RiftRoute came from a package (the .deb):
// those installs are updated through the package manager, not by us. The
// .deb ships /usr/bin/riftrouted and its service runs a copy, so ask dpkg
// whether the package is installed rather than who owns the running file.
func packageManaged(string) bool {
	if runtime.GOOS != "linux" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Status}", "riftroute").Output()
	return err == nil && strings.Contains(string(out), "install ok installed")
}

// bootGuard runs before the database is opened: it confirms, counts or rolls
// back a pending update (see updater.BootGuard).
func bootGuard(current, exe, stateDir, dbPath string, logger *slog.Logger) (*updater.Guard, error) {
	g, err := updater.BootGuard(updater.GuardEnv{
		Current: current, Binary: exe, StateDir: stateDir, DBPath: dbPath,
		DBVersion: store.FileUserVersion, DBMinReader: store.FileMinReader, Log: logger,
	})
	if err != nil {
		logger.Error("update boot guard", "err", err)
	}
	if g == nil {
		g = &updater.Guard{}
	}
	return g, err
}

// confirmWhenServing marks an update on probation healthy once the daemon
// has been up for a while and answers GET /healthz on its socket (an HTTP
// answer, not just an accepted connection). Until then — or if it never
// answers — the boot guard's watchdog decides.
func confirmWhenServing(ctx context.Context, g *updater.Guard, socket string) {
	if !g.Probation() {
		return
	}
	hc := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}},
	}
	wait := 20 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = 5 * time.Second
		resp, err := hc.Get("http://riftrouted/healthz")
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			g.Confirm()
			return
		}
	}
}

// selfTestArgs is the command line the updater runs a staged binary with:
// the running service's own arguments (so a release that dropped a flag the
// service uses fails here, not at restart), pointed at a database copy.
func selfTestArgs(serviceArgs []string, db string) []string {
	out := []string{"-selftest", "-db", db}
	for i := 0; i < len(serviceArgs); i++ {
		a := serviceArgs[i]
		name := strings.TrimLeft(a, "-")
		switch {
		case name == "db" || name == "selftest":
			if name == "db" && !strings.Contains(a, "=") {
				i++ // its value
			}
		case strings.HasPrefix(name, "db=") || strings.HasPrefix(name, "selftest="):
		default:
			out = append(out, a)
		}
	}
	return out
}

// newUpdater builds the daemon's updater.
func newUpdater(ctx context.Context, st *store.Store, proto *safety.Protocol, current, exe, stateDir, dbPath, providerName, channel string,
	restart *atomic.Int32, stop func(), logger *slog.Logger) (*updater.Updater, error) {
	serviceArgs := append([]string(nil), os.Args[1:]...)
	return updater.New(updater.Env{
		Ctx: ctx, Current: current, Channel: channel,
		ServerURL: updater.DefaultServerURL, FallbackURL: updater.DefaultFallbackURL,
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		Binary: exe, StateDir: stateDir, DBPath: dbPath,
		SelfUpdatable: selfUpdatable(exe, providerName),
		Loop:          providerName != "fake",
		Mode: func() domain.UpdateMode {
			p, err := st.LoadPreferences()
			if err != nil {
				return domain.UpdateNotify
			}
			return p.Updates
		},
		Quiesce:  func() (func(), bool, string) { return proto.TryQuiesce(10 * time.Minute) },
		BackupDB: st.BackupTo,
		SelfTest: func(ctx context.Context, bin, db string) error {
			out, err := exec.CommandContext(ctx, bin, selfTestArgs(serviceArgs, db)...).CombinedOutput()
			if err != nil {
				tail := strings.TrimSpace(string(out))
				if len(tail) > 400 {
					tail = tail[len(tail)-400:]
				}
				return fmt.Errorf("%w: %s", err, tail)
			}
			return nil
		},
		Restart: func() {
			restart.Store(updater.RestartExitCode)
			stop()
		},
		Log: logger,
	})
}

// runSelfTest is `riftrouted -selftest`: what a staged update must survive
// before it's allowed to replace the running daemon — open (and migrate) a
// copy of the database and initialise the provider, read-only. It never
// listens, applies or touches the live database.
func runSelfTest(dbPath, providerName string, logger *slog.Logger) error {
	if dbPath == "" {
		return errors.New("-selftest needs -db (a copy of the database)")
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()
	if _, err := st.LoadPreferences(); err != nil {
		return fmt.Errorf("read settings: %w", err)
	}
	prov, err := selectProvider(providerName, logger)
	if err != nil {
		return fmt.Errorf("provider: %w", err)
	}
	caps := prov.Capabilities()
	fmt.Printf("selftest ok: %s, provider %s (%s)\n", buildinfo.Label(buildinfo.Current(version)), prov.Name(), caps.Platform)
	return nil
}
