package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/Amirhat/riftroute/internal/bugreport"
	"github.com/Amirhat/riftroute/internal/buildinfo"
	"github.com/Amirhat/riftroute/internal/domain"
)

// CreateBugReport builds the redacted diagnostics report for the preview:
// the daemon's report plus this app's own section, or — when the daemon
// doesn't answer — what can be gathered without it. Nothing leaves the
// machine; the user reads it, then saves or copies it.
func (a *App) CreateBugReport() domain.BugReport {
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()
	c := bugreport.Client{Name: "RiftRoute app", Build: buildinfo.Current(version)}
	rep, err := a.client.BugReport(ctx)
	if err != nil {
		return bugreport.Offline(ctx, time.Now(), c, err)
	}
	var daemon *domain.Health
	if h, herr := a.client.Health(ctx); herr == nil {
		daemon = &h
	}
	return bugreport.WithClient(ctx, rep, c, daemon)
}

// SaveBugReport writes the previewed report where the user chooses (0600:
// even redacted, it's theirs to share). Returns "" if they cancelled.
func (a *App) SaveBugReport(text string) (string, error) {
	path, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{
		Title:           "Save bug report",
		DefaultFilename: "riftroute-bugreport-" + time.Now().UTC().Format("20060102-150405") + ".txt",
		Filters:         []wruntime.FileFilter{{DisplayName: "Text (*.txt)", Pattern: "*.txt"}},
	})
	if err != nil || path == "" {
		return "", err
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return "", fmt.Errorf("could not write %s: %w", filepath.Base(path), err)
	}
	return path, nil
}

// OpenIssuePage opens the project's new-issue page in the browser, where the
// user attaches the report themselves.
func (a *App) OpenIssuePage() { wruntime.BrowserOpenURL(a.ctx, bugreport.IssueURL) }
