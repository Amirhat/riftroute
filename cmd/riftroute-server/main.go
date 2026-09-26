// Command riftroute-server serves riftroute.tellnew.tech: the bilingual
// landing page and the admin dashboard (later: update API, telemetry ingest,
// bug-report upload). It binds loopback only — Caddy terminates TLS in front
// of it — and refuses any other address.
//
//	riftroute-server serve  -listen 127.0.0.1:7780 -data /var/lib/riftroute-server
//	riftroute-server passwd -data /var/lib/riftroute-server   (prompts; never an argument)
//	riftroute-server publish -data /var/lib/riftroute-server -channel stable -manifest m.json -sig m.json.sig [-rollout 100]
//	riftroute-server version
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/Amirhat/riftroute/internal/buildinfo"
	"github.com/Amirhat/riftroute/internal/server"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "passwd":
		err = passwd(os.Args[2:])
	case "publish":
		err = publish(os.Args[2:])
	case "version":
		fmt.Println(buildinfo.Short(buildinfo.Current(version)))
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "riftroute-server:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: riftroute-server serve|passwd|publish|version [flags]")
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:7780", "loopback address to listen on (Caddy proxies to it)")
	data := fs.String("data", "/var/lib/riftroute-server", "data directory (database, admin password hash)")
	_ = fs.Parse(args)

	if err := requireLoopback(*listen); err != nil {
		return err
	}
	if err := os.MkdirAll(*data, 0o700); err != nil {
		return fmt.Errorf("data directory: %w", err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	build := buildinfo.Current(version)
	srv, err := server.New(server.Config{DataDir: *data, Build: build, Logger: logger, DiskFree: diskFree})
	if err != nil {
		return err
	}
	defer srv.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go srv.Maintain(ctx)

	hs := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	logger.Info("riftroute-server listening", "addr", *listen, "build", buildinfo.Short(build))
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(shut)
	}
	logger.Info("riftroute-server stopped")
	return nil
}

// requireLoopback refuses to serve on anything but loopback: this process has
// no TLS and trusts Caddy in front of it.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("refusing to listen on %q: loopback only (127.0.0.1 or ::1); Caddy serves the public side", addr)
	}
	return nil
}

// passwd sets the admin password: prompted twice without echo on a terminal,
// or read as one line from stdin — never taken as an argument, so it can't
// land in shell history or the process list.
func passwd(args []string) error {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	data := fs.String("data", "/var/lib/riftroute-server", "data directory")
	_ = fs.Parse(args)
	if err := requireDataOwner(*data); err != nil {
		return err
	}

	var pw string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(os.Stderr, "New admin password (at least %d characters): ", server.MinPasswordLen)
		a, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		fmt.Fprint(os.Stderr, "Again: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		if string(a) != string(b) {
			return errors.New("the two passwords don't match")
		}
		pw = string(a)
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("read password from stdin: %w", err)
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	if err := server.SetPassword(*data, pw); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "admin password saved; every existing sign-in and remembered device was signed out")
	return nil
}

// publish installs a signed release manifest as a channel's current release.
// It verifies the signature against the release keys compiled into this
// binary and refuses anything older than what's published.
func publish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	data := fs.String("data", "/var/lib/riftroute-server", "data directory")
	channel := fs.String("channel", "stable", "update channel")
	manifest := fs.String("manifest", "", "manifest.json")
	sig := fs.String("sig", "", "manifest.json.sig")
	rollout := fs.Int("rollout", -1, "starting rollout percent 0–100 (default: 100 for a new version; unchanged when re-publishing the same one)")
	_ = fs.Parse(args)
	if *manifest == "" || *sig == "" {
		return errors.New("-manifest and -sig are required")
	}
	if err := requireDataOwner(*data); err != nil {
		return err
	}
	raw, err := os.ReadFile(*manifest)
	if err != nil {
		return err
	}
	s, err := os.ReadFile(*sig)
	if err != nil {
		return err
	}
	m, err := server.PublishManifest(*data, *channel, raw, s, *rollout, nil, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "published %s %s (%d assets)\n", *channel, m.Version, len(m.Assets))
	return nil
}
