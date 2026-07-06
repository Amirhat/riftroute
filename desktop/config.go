package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/Amirhat/riftroute/internal/apiclient"
	"github.com/Amirhat/riftroute/internal/config"
)

// maxConfigBytes caps an imported config (matches the daemon's own /config limit).
const maxConfigBytes = 1 << 20

// ConfigFile is a declarative config the user picked in the native file dialog,
// read and handed to the frontend for a validate → preview → apply flow so the
// user never has to touch the CLI (`riftroute apply file.yaml` in the window).
type ConfigFile struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	Format  string `json:"format"` // yaml | toml
	Content string `json:"content"`
}

// OpenConfigDialog shows a native open-file dialog for a declarative config and
// returns its contents. An empty Path with a nil error means the user cancelled.
func (a *App) OpenConfigDialog() (ConfigFile, error) {
	path, err := wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{
		Title: "Import RiftRoute config",
		Filters: []wruntime.FileFilter{
			{DisplayName: "RiftRoute config (*.yaml, *.yml, *.toml)", Pattern: "*.yaml;*.yml;*.toml"},
			{DisplayName: "All files", Pattern: "*"},
		},
	})
	if err != nil {
		return ConfigFile{}, err
	}
	if path == "" {
		return ConfigFile{}, nil // cancelled
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ConfigFile{}, fmt.Errorf("could not read %s: %w", filepath.Base(path), err)
	}
	if len(data) > maxConfigBytes {
		return ConfigFile{}, fmt.Errorf("%s is too large (%d bytes; limit %d)", filepath.Base(path), len(data), maxConfigBytes)
	}
	return ConfigFile{
		Path:    path,
		Name:    filepath.Base(path),
		Format:  configFormat(path),
		Content: string(data),
	}, nil
}

// ApplyConfigContent validates and (unless dryRun) applies a declarative config
// over the daemon IPC — the same endpoint the CLI's `apply` uses. A dry run
// returns the plan + line-referenced issues for the preview; a real apply with
// yes=false returns a pending interactive transaction for the commit-confirm
// countdown (the GUI then calls Confirm/Rollback). Never mutates anything on
// dry-run, and validation errors come back as populated Issues (not a thrown
// error), so the UI can render them inline.
func (a *App) ApplyConfigContent(content, format string, dryRun, yes bool) (apiclient.ConfigResult, error) {
	ctx, cancel := a.call()
	defer cancel()
	res, err := a.client.ApplyConfig(ctx, []byte(content), format, dryRun, yes)
	// A 400 (validation failure) is not a transport error for the UI: the Issues in
	// res carry the line-referenced diagnostics we want to show. Surface transport/
	// daemon-unreachable errors, swallow the validation-status error.
	if err != nil && len(res.Issues) > 0 {
		return res, nil
	}
	return res, err
}

// ExportConfigDialog serializes the live configuration (profiles, lists,
// split-DNS) to declarative YAML and writes it where the user chooses via the
// native save dialog — the inverse of the import flow, so anything built visually
// stays reviewable and git-committable. Returns the saved path ("" = cancelled).
func (a *App) ExportConfigDialog() (string, error) {
	ctx, cancel := a.call()
	defer cancel()
	// All three reads must succeed: silently exporting a config missing its lists
	// or split-DNS would produce a "full policy" file that, re-applied, deletes
	// what it omitted.
	profiles, err := a.client.Profiles(ctx)
	if err != nil {
		return "", fmt.Errorf("couldn't read profiles from the daemon: %w", err)
	}
	lists, err := a.client.Lists(ctx)
	if err != nil {
		return "", fmt.Errorf("couldn't read lists from the daemon: %w", err)
	}
	splitDNS, err := a.client.SplitDNS(ctx)
	if err != nil {
		return "", fmt.Errorf("couldn't read split-DNS from the daemon: %w", err)
	}

	data, err := config.FromDomain(profiles, lists, splitDNS).ToYAML()
	if err != nil {
		return "", err
	}
	path, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{
		Title:           "Export RiftRoute config",
		DefaultFilename: "riftroute.yaml",
		Filters: []wruntime.FileFilter{
			{DisplayName: "RiftRoute config (*.yaml)", Pattern: "*.yaml;*.yml"},
		},
	})
	if err != nil || path == "" {
		return "", err // "" = user cancelled
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("could not write %s: %w", filepath.Base(path), err)
	}
	return path, nil
}

func configFormat(path string) string {
	if strings.HasSuffix(strings.ToLower(path), ".toml") {
		return "toml"
	}
	return "yaml"
}
