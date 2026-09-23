package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

var (
	release023 = domain.BuildInfo{ModuleVersion: "v0.2.3", Commit: "260b2e780ff8", CommitTime: "2026-07-08T15:47:47Z"}
	devFix     = domain.BuildInfo{ModuleVersion: "v0.2.4-0.20260813100457-a5e49c21fa47", Commit: "a5e49c21fa47", CommitTime: "2026-08-13T10:04:57Z"}
)

// The real incident: the v0.2.3 release (bundled in an older app) replaced a
// newer dev build of the gateway fix. That install must be refused.
func TestGuardDowngradeRefusesOlderBuild(t *testing.T) {
	err := guardDowngrade(release023, devFix, "/Applications/RiftRoute.app/Contents/Resources/bin/riftrouted", false)
	if err == nil {
		t.Fatal("installing an older build must be refused")
	}
	for _, want := range []string{"refusing to downgrade", "260b2e7", "a5e49c2", "RiftRoute.app", "--allow-downgrade"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	if err := guardDowngrade(release023, devFix, "x", true); err != nil {
		t.Fatalf("--allow-downgrade must override: %v", err)
	}
}

func TestGuardDowngradeAllowsUpgradeSameAndUnknown(t *testing.T) {
	if err := guardDowngrade(devFix, release023, "x", false); err != nil {
		t.Fatalf("upgrade refused: %v", err)
	}
	if err := guardDowngrade(release023, release023, "x", false); err != nil {
		t.Fatalf("reinstalling the same build refused: %v", err)
	}
	if err := guardDowngrade(domain.BuildInfo{}, release023, "x", false); err != nil {
		t.Fatalf("an unorderable build must not be guessed at: %v", err)
	}
}

func TestVerifyRunningWaitsForInstalledBuild(t *testing.T) {
	calls := 0
	health := func(context.Context) (domain.Health, error) {
		calls++
		if calls < 3 {
			return domain.Health{}, errors.New("connection refused") // daemon still starting
		}
		return domain.Health{Build: devFix}, nil
	}
	if err := verifyRunning(context.Background(), devFix, health); err != nil {
		t.Fatalf("verifyRunning: %v", err)
	}
}

// A service manager that kept the old process alive must not pass as success.
func TestVerifyRunningReportsOldProcessStillServing(t *testing.T) {
	old := verifyWindow
	verifyWindow = 700 * time.Millisecond
	t.Cleanup(func() { verifyWindow = old })
	health := func(context.Context) (domain.Health, error) { return domain.Health{Build: release023}, nil }
	err := verifyRunning(context.Background(), devFix, health)
	if err == nil || !strings.Contains(err.Error(), "still runs") || !strings.Contains(err.Error(), "260b2e7") {
		t.Fatalf("want 'still runs <old build>' error, got %v", err)
	}
}

// Daemons that predate build reporting answer with a bare version.
func TestRunningMatchesOldDaemonByVersion(t *testing.T) {
	old := domain.BuildInfo{Version: "0.2.3"} // what a v0.2.3 daemon reports
	if !runningMatches(old, release023) {
		t.Fatal("restarting an installed 0.2.3 must verify against the 0.2.3 that answers")
	}
	if runningMatches(old, devFix) {
		t.Fatal("0.2.3 still serving after installing a newer build must fail verification")
	}
}
