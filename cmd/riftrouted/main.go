// Command riftrouted is the privileged daemon: it owns route mutation, network
// monitoring, reconciliation, snapshots, the watchdog, persistence, and the
// local UDS API (spec §3.1). It is persistent — its lifetime is not tied to any
// GUI. In M0 it serves the read-only API backed by the fake provider so the
// whole UI/CLI spine can be developed without root or a real network.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Amirhat/riftroute/internal/api"
	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/platform"
	"github.com/Amirhat/riftroute/internal/provider"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/store"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "riftrouted:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		socketPath   string
		dbPath       string
		providerName string
		logLevel     string
		pushInterval time.Duration
		showVersion  bool
	)
	flag.StringVar(&socketPath, "socket", "", "Unix domain socket path (default: platform-specific)")
	flag.StringVar(&dbPath, "db", "", "SQLite database path (default: platform-specific)")
	flag.StringVar(&providerName, "provider", "fake", "route provider: fake|auto (M0 default: fake)")
	flag.StringVar(&logLevel, "log", "info", "log level: debug|info|warn|error")
	flag.DurationVar(&pushInterval, "push-interval", 3*time.Second, "state broadcast interval for live UI (0 disables)")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(version)
		return nil
	}

	logger := newLogger(logLevel)
	paths := platform.DefaultPaths()
	if socketPath == "" {
		socketPath = paths.Socket
	}
	if dbPath == "" {
		dbPath = paths.DB
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	prov, err := selectProvider(providerName, logger)
	if err != nil {
		return err
	}
	logger.Info("provider selected", "provider", prov.Name())

	svc := core.New(prov, st, version)
	allowUID := uint32(os.Getuid())
	srv := api.NewServer(svc, st, allowUID, version, logger)

	ln, err := listen(socketPath, logger)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if pushInterval > 0 {
		go broadcastLoop(ctx, srv, pushInterval)
	}

	logger.Info("riftrouted listening", "socket", socketPath, "db", dbPath, "version", version, "uid", allowUID)
	serveErr := srv.Serve(ctx, ln)

	// Clean up the socket so the next launch starts fresh (spec/AGENTS §4).
	_ = os.Remove(socketPath)
	if serveErr != nil {
		return serveErr
	}
	logger.Info("riftrouted stopped")
	return nil
}

// listen creates the UDS listener, removing any stale socket and locking down
// permissions to 0600 (defense in depth on top of peer-cred authz).
func listen(socketPath string, logger *slog.Logger) (net.Listener, error) {
	if _, err := os.Stat(socketPath); err == nil {
		// A stale socket from a crashed instance, or a live one. Probe it; if a
		// daemon answers, refuse rather than clobber it.
		if c, derr := net.DialTimeout("unix", socketPath, 300*time.Millisecond); derr == nil {
			_ = c.Close()
			return nil, fmt.Errorf("another riftrouted appears to be running at %s", socketPath)
		}
		logger.Warn("removing stale socket", "socket", socketPath)
		_ = os.Remove(socketPath)
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return ln, nil
}

func selectProvider(name string, logger *slog.Logger) (provider.RouteProvider, error) {
	switch name {
	case "fake":
		return fake.New(), nil
	case "auto", "real":
		p := realProvider()
		if p.Name() == "unsupported" {
			logger.Warn("no native provider for this platform; falling back to unsupported (reads will error)")
		}
		return p, nil
	default:
		return nil, fmt.Errorf("unknown provider %q (want fake|auto)", name)
	}
}

func broadcastLoop(ctx context.Context, srv *api.Server, interval time.Duration) {
	// M0 liveness: periodically push state so the UI's uptime/clock advances and
	// the SSE→Wails→TanStack pipeline is exercised. Replaced by change-driven
	// events once netmon lands (M3).
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			srv.BroadcastState(ctx)
		}
	}
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
