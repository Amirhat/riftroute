package main

import (
	"context"
	"fmt"
	"time"

	"github.com/Amirhat/riftroute/internal/buildinfo"
	"github.com/Amirhat/riftroute/internal/domain"
)

// guardDowngrade refuses to install a daemon older than the one already
// installed. The trap it closes: reinstalling from an older app bundle (or an
// old release download) silently replaced a newer build — on a real machine
// the v0.2.3 release overwrote a dev build carrying the fix being tested.
// Unorderable builds (no VCS info) are allowed; so is an explicit override.
func guardDowngrade(candidate, current domain.BuildInfo, from string, allow bool) error {
	c, ok := buildinfo.Compare(candidate, current)
	if !ok || c >= 0 || allow {
		return nil
	}
	return fmt.Errorf("refusing to downgrade the daemon:\n"+
		"  installed: %s\n"+
		"  candidate: %s\n"+
		"  (from %s — an older app bundle or build?)\n"+
		"re-run with --allow-downgrade if this is intended",
		buildinfo.Short(current), buildinfo.Short(candidate), from)
}

// runningMatches reports whether the daemon now serving is the build that was
// just installed (same commit and dirty flag — the most a dirty build allows).
// A daemon that predates build reporting sends only its version; it matches
// when that version equals the installed one — so reinstalling/restarting
// 0.2.3 passes, while 0.2.3 still serving after an upgrade does not.
func runningMatches(running, want domain.BuildInfo) bool {
	if want.Commit == "" {
		return true
	}
	if running.Commit == "" {
		c, ok := buildinfo.Compare(running, want)
		// Nothing to compare (e.g. an old dev daemon reporting only a
		// git-describe version): don't fail a restart we can't judge.
		return !ok || c == 0
	}
	return running.Commit == want.Commit && running.Modified == want.Modified
}

// verifyWindow bounds how long verifyRunning waits for the new daemon.
var verifyWindow = 10 * time.Second

// verifyRunning waits for the daemon to report the installed build, so a
// service manager that kept the old process alive can't pass as success.
func verifyRunning(ctx context.Context, want domain.BuildInfo, health func(context.Context) (domain.Health, error)) error {
	if want.Commit == "" {
		return nil // nothing to compare against
	}
	deadline := time.Now().Add(verifyWindow)
	var last domain.Health
	var lastErr error
	for time.Now().Before(deadline) {
		hctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		last, lastErr = health(hctx)
		cancel()
		if lastErr == nil && runningMatches(last.Build, want) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	if lastErr != nil {
		return fmt.Errorf("installed %s, but the daemon did not answer: %w", buildinfo.Short(want), lastErr)
	}
	return fmt.Errorf("installed %s, but the daemon still runs %s — restart it: sudo riftroute daemon restart",
		buildinfo.Short(want), buildinfo.Short(last.Build))
}
