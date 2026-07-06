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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Amirhat/riftroute/internal/api"
	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/killswitch"
	"github.com/Amirhat/riftroute/internal/netmon"
	"github.com/Amirhat/riftroute/internal/platform"
	"github.com/Amirhat/riftroute/internal/provider"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/reconcile"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/splitdns"
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
		autoApply    bool
		pollInterval time.Duration
		showVersion  bool
		allowUIDFlag int
	)
	flag.StringVar(&socketPath, "socket", "", "Unix domain socket path (default: platform-specific)")
	flag.StringVar(&dbPath, "db", "", "SQLite database path (default: platform-specific)")
	flag.StringVar(&providerName, "provider", "fake", "route provider: fake|auto (M0 default: fake)")
	flag.StringVar(&logLevel, "log", "info", "log level: debug|info|warn|error")
	flag.DurationVar(&pushInterval, "push-interval", 3*time.Second, "state broadcast interval for live UI (0 disables)")
	flag.BoolVar(&autoApply, "auto-apply", true, "reconcile automatically on network changes (VPN up/down, etc.)")
	flag.DurationVar(&pollInterval, "poll-interval", 2*time.Second, "network-change poll interval")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.IntVar(&allowUIDFlag, "allow-uid", -1, "uid permitted to call mutating endpoints (default: current user; the installer sets this to the desktop user so an unprivileged GUI/CLI can control a root daemon)")
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
	proto := safety.NewProtocol(prov, st, safety.RealClock{}, nil, prov.Capabilities().Platform, logger)

	// Crash recovery, step 1: replay the write-ahead journal. Any transaction that
	// was in flight (or on probation) at the last shutdown is reverted to its
	// pre-change state — fail-safe, and the only recovery that works on macOS.
	if reverted, perr := proto.RecoverPending(context.Background()); perr != nil {
		logger.Warn("pending-tx recovery on startup failed", "err", perr)
	} else if reverted > 0 {
		logger.Info("reverted in-flight transactions on startup (crash recovery)", "count", reverted)
	}

	// Crash recovery, step 2: re-assert/repair owned routes against the kernel
	// (spec §2.5/§13). No-op on a fresh DB.
	if added, removed, rerr := proto.ReconcileOwnership(context.Background()); rerr != nil {
		logger.Warn("ownership reconcile on startup failed", "err", rerr)
	} else if added > 0 || removed > 0 {
		logger.Info("reconciled ownership on startup", "re-added", added, "removed", removed)
	}

	// Auto-apply is a runtime toggle (Settings switch → PUT /autoapply). The
	// persisted choice wins over the flag default so it survives restarts.
	if v, ok, err := st.GetSetting("auto_apply"); err == nil && ok {
		autoApply = v == "true"
	}
	var autoApplyOn atomic.Bool
	autoApplyOn.Store(autoApply)
	svc.SetAutoApply(autoApply)
	// allowUID is the uid permitted to call mutating endpoints. It defaults to the
	// daemon's own uid, but the installer passes -allow-uid <desktop user> so an
	// unprivileged GUI/CLI can drive a root-installed daemon.
	allowUID := uint32(os.Getuid())
	if allowUIDFlag >= 0 {
		allowUID = uint32(allowUIDFlag)
	}
	srv := api.NewServer(svc, st, proto, allowUID, version, logger)
	srv.SetAutoApplyControl(func(on bool) {
		autoApplyOn.Store(on)
		svc.SetAutoApply(on)
		logger.Info("auto-apply toggled", "enabled", on)
	})

	// Fake-only debug hook so auto-apply can be demonstrated against a running
	// daemon by toggling the simulated VPN (never wired for real providers).
	var ks killswitch.Manager = killswitch.New()
	var sdns splitdns.Manager = splitdns.New()
	if fp, ok := prov.(*fake.Provider); ok {
		srv.SetDebugVPN(fp.SetVPN)
		ks = &killswitch.Fake{}        // never touch a real firewall under -provider fake
		sdns = &splitdns.FakeManager{} // never touch real system DNS under -provider fake
	}
	srv.SetKillSwitch(ks)
	srv.SetSplitDNS(sdns)
	svc.SetKillSwitchStatus(func() bool {
		on, _ := ks.Enabled(context.Background())
		return on
	})

	// Re-apply the persisted split-DNS selection so per-domain resolvers survive
	// a daemon restart (best-effort; an empty/unset selection is a no-op).
	if routes, err := st.LoadSplitDNS(); err != nil {
		logger.Warn("split-dns load on startup failed", "err", err)
	} else if len(routes) > 0 {
		if err := sdns.Apply(context.Background(), routes); err != nil {
			logger.Warn("split-dns re-apply on startup failed", "err", err)
		} else {
			logger.Info("re-applied persisted split-DNS", "routes", len(routes))
		}
	}

	ln, err := listen(socketPath, logger)
	if err != nil {
		return err
	}
	// When serving a different uid than our own (root daemon ↔ desktop-user GUI),
	// hand socket ownership to that user so it can connect; writes stay gated by
	// peer-cred authz (allowUID). Same-uid (dev) keeps the default 0600.
	if int(allowUID) != os.Getuid() {
		if err := os.Chown(socketPath, int(allowUID), -1); err != nil {
			logger.Warn("chown socket to allow-uid failed", "uid", allowUID, "err", err)
		} else if err := os.Chmod(socketPath, 0o660); err != nil {
			logger.Warn("chmod socket failed", "err", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if pushInterval > 0 {
		go supervise(ctx, logger, "broadcast", func(c context.Context) { broadcastLoop(c, srv, pushInterval) })
	}

	// Auto-apply: watch for network changes and reconcile safely (guard kept,
	// manual confirm skipped). Routing keeps working with no UI open (spec §3.1).
	// The loops ALWAYS run and gate each pass on the runtime toggle — so flipping
	// auto-apply on from Settings takes effect immediately, without a daemon
	// restart. Each loop is supervised: a panic is recovered + the loop restarted,
	// so a single bad snapshot can never crash the daemon (which would kill an
	// armed watchdog and strand the user).
	poller := netmon.NewPoller(prov, pollInterval)
	rec := reconcile.New(svc, proto, logger, 500*time.Millisecond, autoApplyOn.Load)
	go supervise(ctx, logger, "poller", poller.Run)
	go supervise(ctx, logger, "reconciler", func(c context.Context) { rec.Run(c, poller.Events()) })
	go supervise(ctx, logger, "domain-reresolve", func(c context.Context) { domainReresolveLoop(c, svc, rec, logger) })
	logger.Info("auto-apply loops running", "enabled", autoApplyOn.Load(), "poll", pollInterval)

	logger.Info("riftrouted listening", "socket", socketPath, "db", dbPath, "version", version, "uid", allowUID)
	serveErr := srv.Serve(ctx, ln)

	// Graceful shutdown: resolve any in-flight transactions (commit auto-applied,
	// roll back unconfirmed) so a clean reboot doesn't trip crash-recovery. An
	// actual crash never reaches here, leaving the journal for RecoverPending.
	proto.ShutdownResolve()

	// Clean up the socket so the next launch starts fresh (spec/AGENTS §4).
	_ = os.Remove(socketPath)
	if serveErr != nil {
		return serveErr
	}
	logger.Info("riftrouted stopped")
	return nil
}

// supervise runs a long-lived loop, recovering from panics and restarting it
// (with a short backoff) until ctx is done. A panic in one background loop must
// never crash the daemon — that would tear down every goroutine, including an
// armed watchdog mid-transaction, and strand the user.
func supervise(ctx context.Context, logger *slog.Logger, name string, fn func(context.Context)) {
	for ctx.Err() == nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("recovered panic in loop; restarting", "loop", name, "panic", r)
				}
			}()
			fn(ctx)
		}()
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
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

// domainReresolveLoop periodically re-resolves domain rules; when a CDN's
// addresses change it reconciles so the managed routes follow (spec §6).
func domainReresolveLoop(ctx context.Context, svc *core.Service, rec *reconcile.Reconciler, logger *slog.Logger) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if svc.RefreshDomains(ctx) {
				logger.Info("domain addresses changed; reconciling")
				_, _ = rec.Reconcile(ctx)
			}
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
