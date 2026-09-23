package domain

// BuildInfo identifies one binary build: the version stamped at link time plus
// the VCS facts the Go toolchain embeds. It answers "is the code I just built
// actually what's running?" and lets install refuse accidental downgrades.
type BuildInfo struct {
	// Version is the link-time stamp (-X main.version); "dev" when unset.
	Version string `json:"version"`
	// ModuleVersion is derived by the toolchain from VCS tags: "v0.2.3" on a
	// tagged commit, a pseudo-version between tags, "+dirty" for modified trees.
	ModuleVersion string `json:"module_version,omitempty"`
	Commit        string `json:"commit,omitempty"`
	CommitTime    string `json:"commit_time,omitempty"` // RFC 3339
	// Modified means the tree had uncommitted changes when this was built.
	Modified  bool   `json:"modified,omitempty"`
	GoVersion string `json:"go_version,omitempty"`
	Platform  string `json:"platform,omitempty"` // GOOS/GOARCH
	// Summary is the one-line human form, e.g. "0.2.3 (260b2e7, 2026-07-08)".
	Summary string `json:"summary,omitempty"`
}
