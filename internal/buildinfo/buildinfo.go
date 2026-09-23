// Package buildinfo identifies RiftRoute binaries from what the Go toolchain
// embeds in them (commit, commit time, dirty flag, tag-derived module version),
// both for the running process and for a binary file on disk — the latter read
// without executing it, so install can compare builds safely as root.
package buildinfo

import (
	"debug/buildinfo"
	"fmt"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// Current describes the running binary. version is its link-time stamp.
func Current(version string) domain.BuildInfo {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return domain.BuildInfo{Version: version, Platform: runtime.GOOS + "/" + runtime.GOARCH}
	}
	return fromGo(bi, version)
}

// ReadFile describes the Go binary at path without running it. The link-time
// version is not recoverable from a -trimpath build, so Version is left empty
// and callers fall back to ModuleVersion.
func ReadFile(path string) (domain.BuildInfo, error) {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return domain.BuildInfo{}, fmt.Errorf("read build info of %s: %w", path, err)
	}
	return fromGo(bi, ""), nil
}

func fromGo(bi *debug.BuildInfo, version string) domain.BuildInfo {
	out := domain.BuildInfo{Version: version, GoVersion: bi.GoVersion}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		out.ModuleVersion = v
	}
	var goos, goarch string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			out.Commit = s.Value
		case "vcs.time":
			out.CommitTime = s.Value
		case "vcs.modified":
			out.Modified = s.Value == "true"
		case "GOOS":
			goos = s.Value
		case "GOARCH":
			goarch = s.Value
		}
	}
	if goos != "" && goarch != "" {
		out.Platform = goos + "/" + goarch
	}
	out.Summary = Short(out)
	return out
}

// pseudoVersion matches a Go pseudo-version (a build between tags), capturing
// the base version and any "+dirty" suffix.
var pseudoVersion = regexp.MustCompile(`^v(\d+\.\d+\.\d+)-(?:[0-9A-Za-z.-]+\.)?\d{14}-[0-9a-f]{12}(\+[0-9A-Za-z.-]+)?$`)

// Label is the human version: the link-time stamp, else the toolchain's — with
// pseudo-versions shortened to "0.2.4-dev" (Short adds the commit and date).
func Label(b domain.BuildInfo) string {
	switch {
	case b.Version != "" && b.Version != "dev":
		return b.Version
	case b.ModuleVersion != "":
		if m := pseudoVersion.FindStringSubmatch(b.ModuleVersion); m != nil {
			return m[1] + "-dev" + m[2]
		}
		return strings.TrimPrefix(b.ModuleVersion, "v")
	case b.Version != "":
		return b.Version
	}
	return "unknown"
}

// ShortCommit is the abbreviated commit, suffixed "-dirty" for modified trees.
func ShortCommit(b domain.BuildInfo) string {
	c := b.Commit
	if len(c) > 7 {
		c = c[:7]
	}
	if c != "" && b.Modified {
		c += "-dirty"
	}
	return c
}

// Short renders e.g. "0.2.3 (260b2e7, 2026-07-08)".
func Short(b domain.BuildInfo) string {
	var meta []string
	if c := ShortCommit(b); c != "" {
		meta = append(meta, c)
	}
	if t, err := time.Parse(time.RFC3339, b.CommitTime); err == nil {
		meta = append(meta, t.UTC().Format("2006-01-02"))
	}
	if len(meta) == 0 {
		return Label(b)
	}
	return Label(b) + " (" + strings.Join(meta, ", ") + ")"
}

// SameBuild reports whether a and b are provably the same build. Builds from a
// modified tree can share a commit yet differ, so they never compare equal.
func SameBuild(a, b domain.BuildInfo) bool {
	return a.Commit != "" && a.Commit == b.Commit && !a.Modified && !b.Modified
}

// Compare orders two builds: -1 if a is older than b, +1 if newer, 0 if the
// same release. ok is false when neither the module versions nor the commit
// times allow an ordering (e.g. a build without VCS information).
func Compare(a, b domain.BuildInfo) (cmp int, ok bool) {
	if c, ok := compareSemver(semverOf(a), semverOf(b)); ok && c != 0 {
		return c, true
	}
	ta, errA := time.Parse(time.RFC3339, a.CommitTime)
	tb, errB := time.Parse(time.RFC3339, b.CommitTime)
	if errA == nil && errB == nil {
		switch {
		case ta.Before(tb):
			return -1, true
		case ta.After(tb):
			return 1, true
		}
		return 0, true
	}
	if c, ok := compareSemver(semverOf(a), semverOf(b)); ok {
		return c, true
	}
	return 0, false
}

// semverOf is the build's orderable version: the toolchain's module version,
// else — for daemons that predate build reporting and send only their
// link-time stamp — a plain release version like "0.2.3". A git-describe
// stamp ("0.2.3-4-gabc") is NOT used: semver would read it as a pre-release
// of 0.2.3, i.e. older, when it is actually newer.
func semverOf(b domain.BuildInfo) string {
	if b.ModuleVersion != "" {
		return b.ModuleVersion
	}
	if v := "v" + b.Version; releaseOnly.MatchString(v) {
		return v
	}
	return ""
}

var releaseOnly = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// compareSemver implements semver 2.0 precedence, including pre-release
// identifiers — which is what orders Go pseudo-versions
// (v0.2.4-0.20260813100457-a5e49c21fa47 sorts after v0.2.3, before v0.2.4).
// Build metadata ("+dirty") is ignored, as the spec requires.
func compareSemver(a, b string) (int, bool) {
	pa, ok1 := parseSemver(a)
	pb, ok2 := parseSemver(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	for i := 0; i < 3; i++ {
		if pa.core[i] != pb.core[i] {
			return sign(pa.core[i] - pb.core[i]), true
		}
	}
	switch {
	case len(pa.pre) == 0 && len(pb.pre) == 0:
		return 0, true
	case len(pa.pre) == 0:
		return 1, true // a release outranks its pre-releases
	case len(pb.pre) == 0:
		return -1, true
	}
	for i := 0; i < len(pa.pre) && i < len(pb.pre); i++ {
		if c := comparePre(pa.pre[i], pb.pre[i]); c != 0 {
			return c, true
		}
	}
	return sign(len(pa.pre) - len(pb.pre)), true
}

type semver struct {
	core [3]int
	pre  []string
}

func parseSemver(v string) (semver, bool) {
	if !strings.HasPrefix(v, "v") {
		return semver{}, false
	}
	v = v[1:]
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	var out semver
	if i := strings.IndexByte(v, '-'); i >= 0 {
		out.pre = strings.Split(v[i+1:], ".")
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, false
		}
		out.core[i] = n
	}
	return out, true
}

func comparePre(a, b string) int {
	na, errA := strconv.Atoi(a)
	nb, errB := strconv.Atoi(b)
	switch {
	case errA == nil && errB == nil:
		return sign(na - nb)
	case errA == nil:
		return -1 // numeric identifiers have lower precedence
	case errB == nil:
		return 1
	}
	return strings.Compare(a, b)
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// Mismatch explains, in one line, how a client build relates to the daemon it
// talks to — or "" when they match or can't be ordered. Clients print it so a
// daemon left on an older build (the fix "doesn't work") is obvious.
func Mismatch(client, daemon domain.BuildInfo) string {
	if SameBuild(client, daemon) {
		return ""
	}
	c, ok := Compare(daemon, client)
	if !ok {
		return ""
	}
	switch {
	case c < 0:
		return fmt.Sprintf("the daemon (%s) is older than this client (%s) — install the newer daemon", Short(daemon), Short(client))
	case c > 0:
		return fmt.Sprintf("this client (%s) is older than the daemon (%s) — update the app/CLI", Short(client), Short(daemon))
	}
	return ""
}
