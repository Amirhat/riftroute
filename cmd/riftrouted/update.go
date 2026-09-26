package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
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

// packageManaged reports whether a package manager owns the file (a .deb
// install): those are updated through the package manager, not by us.
func packageManaged(path string) bool {
	if runtime.GOOS != "linux" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "dpkg-query", "-S", path).Run() == nil
}

// bootGuard runs before the database is opened: it confirms, counts or rolls
// back a pending update (see updater.BootGuard).
func bootGuard(current, exe, stateDir, dbPath string, logger *slog.Logger) (*updater.Guard, error) {
	g, err := updater.BootGuard(updater.GuardEnv{
		Current: current, Binary: exe, StateDir: stateDir, DBPath: dbPath,
		DBVersion: store.FileUserVersion, Log: logger,
	})
	if err != nil {
		logger.Error("update boot guard", "err", err)
	}
	if g == nil {
		g = &updater.Guard{}
	}
	return g, err
}

// confirmWhenServing marks an update healthy once the daemon has been up and
// answering on its socket for a while.
func confirmWhenServing(ctx context.Context, g *updater.Guard, socket string) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}
	c, err := net.DialTimeout("unix", socket, 2*time.Second)
	if err != nil {
		return // not serving: the boot guard's watchdog counts this start as failed
	}
	_ = c.Close()
	g.Confirm()
}

// newUpdater builds the daemon's updater.
func newUpdater(st *store.Store, proto *safety.Protocol, current, exe, stateDir, dbPath, providerName, channel string,
	restart *atomic.Int32, stop func(), logger *slog.Logger) (*updater.Updater, error) {
	return updater.New(updater.Env{
		Current: current, Channel: channel,
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
		Idle: func() (bool, string) {
			busy, last := proto.Busy()
			if busy {
				return false, "a change is being applied or awaits confirmation"
			}
			if !last.IsZero() && time.Since(last) < 10*time.Minute {
				return false, "a change was made in the last 10 minutes"
			}
			return true, ""
		},
		BackupDB: st.BackupTo,
		SelfTest: func(ctx context.Context, bin, db string) error {
			out, err := exec.CommandContext(ctx, bin, "-selftest", "-db", db, "-provider", providerName).CombinedOutput()
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
