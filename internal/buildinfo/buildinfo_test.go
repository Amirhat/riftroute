package buildinfo

import (
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

func TestCompareSemverOrdersReleasesAndPseudoVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v0.2.3", "v0.2.3", 0},
		{"v0.2.3", "v0.2.4", -1},
		{"v0.10.0", "v0.9.9", 1},
		// Pseudo-version after v0.2.3: newer than the tag it builds on…
		{"v0.2.4-0.20260813100457-a5e49c21fa47", "v0.2.3", 1},
		// …older than the release it precedes…
		{"v0.2.4-0.20260813100457-a5e49c21fa47", "v0.2.4", -1},
		// …and ordered by commit time among themselves.
		{"v0.2.4-0.20260813100457-a5e49c21fa47", "v0.2.4-0.20260901000000-0123456789ab", -1},
		{"v0.2.3+dirty", "v0.2.3", 0}, // build metadata never affects precedence
		{"v1.0.0-rc.1", "v1.0.0-rc.2", -1},
		{"v1.0.0-2", "v1.0.0-rc", -1}, // numeric < alphanumeric
		{"v1.0.0-rc", "v1.0.0-rc.1", -1},
	}
	for _, c := range cases {
		got, ok := compareSemver(c.a, c.b)
		if !ok || got != c.want {
			t.Errorf("compareSemver(%q, %q) = %d ok=%v, want %d", c.a, c.b, got, ok, c.want)
		}
	}
	for _, bad := range []string{"", "(devel)", "0.2.3", "v0.2", "vX.Y.Z"} {
		if _, ok := compareSemver(bad, "v0.2.3"); ok {
			t.Errorf("compareSemver(%q) should be unorderable", bad)
		}
	}
}

// The case that bit a real install: the v0.2.3 release (tagged) replaced a
// newer dev build of the gateway fix. That must read as a downgrade.
func TestCompareDetectsReleaseOverNewerDevBuild(t *testing.T) {
	release := domain.BuildInfo{ModuleVersion: "v0.2.3", Commit: "260b2e780ff8", CommitTime: "2026-07-08T15:47:47Z"}
	dev := domain.BuildInfo{ModuleVersion: "v0.2.4-0.20260813100457-a5e49c21fa47", Commit: "a5e49c21fa47", CommitTime: "2026-08-13T10:04:57Z"}
	if c, ok := Compare(release, dev); !ok || c != -1 {
		t.Fatalf("Compare(release, newer dev) = %d ok=%v, want -1", c, ok)
	}
	if c, ok := Compare(dev, release); !ok || c != 1 {
		t.Fatalf("Compare(newer dev, release) = %d ok=%v, want 1", c, ok)
	}
}

// Daemons that predate build reporting send only "0.2.3" — still orderable
// against a newer client, so the "old daemon still running" note appears.
func TestCompareUsesPlainReleaseStampOfOldDaemons(t *testing.T) {
	oldDaemon := domain.BuildInfo{Version: "0.2.3"}
	client := domain.BuildInfo{ModuleVersion: "v0.2.4-0.20260923022032-4c7deb0177d6+dirty"}
	if c, ok := Compare(oldDaemon, client); !ok || c != -1 {
		t.Fatalf("Compare(old 0.2.3 daemon, newer client) = %d ok=%v, want -1", c, ok)
	}
	if m := Mismatch(client, oldDaemon); !strings.Contains(m, "daemon (0.2.3) is older") {
		t.Fatalf("mismatch note = %q", m)
	}
	// A git-describe stamp must not be misread as a pre-release of its tag.
	if _, ok := Compare(domain.BuildInfo{Version: "0.2.3-4-gabc1234"}, domain.BuildInfo{Version: "0.2.3"}); ok {
		t.Fatal("git-describe stamps must be unorderable, not older than their tag")
	}
}

func TestCompareFallsBackToCommitTimeAndReportsUnknown(t *testing.T) {
	older := domain.BuildInfo{Commit: "a", CommitTime: "2026-01-01T00:00:00Z"}
	newer := domain.BuildInfo{Commit: "b", CommitTime: "2026-02-01T00:00:00Z"}
	if c, ok := Compare(older, newer); !ok || c != -1 {
		t.Fatalf("got %d ok=%v, want -1 via commit time", c, ok)
	}
	if _, ok := Compare(domain.BuildInfo{}, newer); ok {
		t.Fatal("a build without VCS info must be unorderable, not guessed")
	}
}

func TestShortAndLabel(t *testing.T) {
	b := domain.BuildInfo{Version: "0.2.3", Commit: "260b2e780ff88915", CommitTime: "2026-07-08T15:47:47Z"}
	if got := Short(b); got != "0.2.3 (260b2e7, 2026-07-08)" {
		t.Fatalf("Short = %q", got)
	}
	dirty := domain.BuildInfo{Version: "dev", ModuleVersion: "v0.2.4-0.2026+dirty", Commit: "a5e49c21fa47", Modified: true}
	if got := Short(dirty); got != "0.2.4-0.2026+dirty (a5e49c2-dirty)" {
		t.Fatalf("Short(dirty) = %q", got)
	}
}

func TestLabelShortensPseudoVersions(t *testing.T) {
	cases := map[string]string{
		"v0.2.4-0.20260923022032-4c7deb0177d6+dirty": "0.2.4-dev+dirty",
		"v0.2.4-0.20260813100457-a5e49c21fa47":       "0.2.4-dev",
		"v0.0.0-20260813100457-a5e49c21fa47":         "0.0.0-dev",
		"v1.0.0-rc.1.0.20260813100457-a5e49c21fa47":  "1.0.0-dev",
		"v0.2.3":       "0.2.3",
		"v0.2.3+dirty": "0.2.3+dirty",
	}
	for mod, want := range cases {
		if got := Label(domain.BuildInfo{ModuleVersion: mod}); got != want {
			t.Errorf("Label(%q) = %q, want %q", mod, got, want)
		}
	}
}

func TestSameBuildNeverTrustsDirtyTrees(t *testing.T) {
	a := domain.BuildInfo{Commit: "abc"}
	if !SameBuild(a, a) {
		t.Fatal("identical clean builds must match")
	}
	d := domain.BuildInfo{Commit: "abc", Modified: true}
	if SameBuild(d, d) {
		t.Fatal("two dirty builds of one commit can differ; must not match")
	}
	if SameBuild(domain.BuildInfo{}, domain.BuildInfo{}) {
		t.Fatal("builds without a commit must not match")
	}
}

// ReadFile works on a real Go binary without executing it.
func TestReadFileOnRealBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	b, err := ReadFile(exe)
	if err != nil {
		t.Fatalf("ReadFile(test binary): %v", err)
	}
	if !strings.HasPrefix(b.GoVersion, "go") || b.Platform == "" {
		t.Fatalf("incomplete build info: %+v", b)
	}
	if _, err := ReadFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file must error")
	}
}

func TestWatcherReportsReplacedBinary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "riftrouted")
	if err := os.WriteFile(path, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	running := domain.BuildInfo{Version: "0.2.3", Commit: "old"}
	onDisk := running
	w := newWatcher(path, running, func(string) (domain.BuildInfo, error) { return onDisk, nil })

	if req, _ := w.Check(); req {
		t.Fatal("untouched binary must not require a restart")
	}

	// Same build reinstalled (content rewritten, identity unchanged).
	replace(t, path, "v1-reinstalled")
	if req, why := w.Check(); req {
		t.Fatalf("reinstalling the same build must not require a restart: %s", why)
	}

	// A different build lands on disk.
	onDisk = domain.BuildInfo{Version: "", ModuleVersion: "v0.2.4", Commit: "new"}
	replace(t, path, "v2-new-build")
	req, why := w.Check()
	if !req || !strings.Contains(why, "0.2.4") || !strings.Contains(why, "running 0.2.3") {
		t.Fatalf("new build on disk: required=%v reason=%q", req, why)
	}

	// Unreadable replacement still requires a restart.
	w2 := newWatcher(path, running, func(string) (domain.BuildInfo, error) { return domain.BuildInfo{}, errors.New("not a Go binary") })
	replace(t, path, "garbage-bytes!!")
	if req, _ := w2.Check(); !req {
		t.Fatal("an unreadable replacement must still require a restart")
	}

	_ = os.Remove(path)
	if req, _ := w.Check(); !req {
		t.Fatal("a removed binary must be reported")
	}
}

func TestNilWatcherIsInert(t *testing.T) {
	var w *Watcher
	if req, _ := w.Check(); req || w.Path() != "" {
		t.Fatal("nil watcher must report nothing")
	}
}

// replace swaps the file like an installer does (write temp + rename), with a
// distinct size and mtime so the change is visible even on coarse clocks.
func replace(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Duration(len(content)) * time.Second)
	if err := os.Chtimes(tmp, future, future); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func TestMismatchNamesTheOlderSide(t *testing.T) {
	old := domain.BuildInfo{ModuleVersion: "v0.2.3", Commit: "a"}
	neu := domain.BuildInfo{ModuleVersion: "v0.2.4", Commit: "b"}
	if m := Mismatch(neu, old); !strings.Contains(m, "daemon") || !strings.Contains(m, "older than this client") {
		t.Fatalf("old daemon, new client: %q", m)
	}
	if m := Mismatch(old, neu); !strings.Contains(m, "this client") || !strings.Contains(m, "older than the daemon") {
		t.Fatalf("new daemon, old client: %q", m)
	}
	if m := Mismatch(old, old); m != "" {
		t.Fatalf("same build must not warn: %q", m)
	}
	if m := Mismatch(domain.BuildInfo{}, old); m != "" {
		t.Fatalf("unorderable builds must not guess: %q", m)
	}
}

// Wails-built apps carry no toolchain VCS stamp; link-time values fill in.
func TestCurrentFallsBackToLinkTimeCommit(t *testing.T) {
	oc, ot, om := linkCommit, linkCommitTime, linkModified
	t.Cleanup(func() { linkCommit, linkCommitTime, linkModified = oc, ot, om })
	linkCommit, linkCommitTime, linkModified = "1e3a0c21e2c56270", "2026-09-23T02:51:56Z", "true"

	got := Current("0.2.3-9-g1e3a0c2")
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				t.Skip("test binary is VCS-stamped; the toolchain value wins")
			}
		}
	}
	if got.Commit != linkCommit || got.CommitTime != linkCommitTime || !got.Modified {
		t.Fatalf("link-time identity not used: %+v", got)
	}
	if got.Summary != "0.2.3-9-g1e3a0c2 (1e3a0c2-dirty, 2026-09-23)" {
		t.Fatalf("summary = %q", got.Summary)
	}
}

// Untagged builds (shallow clone, fork, manual CI run) are stamped v0.0.0-…;
// that must not make them "older" than every release.
func TestCompareUntaggedBuildsByCommitTime(t *testing.T) {
	untaggedNew := domain.BuildInfo{ModuleVersion: "v0.0.0-20260920101010-abcdefabcdef", Commit: "abcdef", CommitTime: "2026-09-20T10:10:10Z"}
	release := domain.BuildInfo{ModuleVersion: "v0.2.3", Commit: "260b2e7", CommitTime: "2026-07-08T15:47:47Z"}
	if c, ok := Compare(untaggedNew, release); !ok || c != 1 {
		t.Fatalf("untagged newer build vs release = %d ok=%v, want +1 (by commit time)", c, ok)
	}
}

// Identical bytes are the same program even when build metadata can't prove
// it (two dirty builds of one commit look alike either way).
func TestWatcherUsesContentForDirtyBuilds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "riftrouted")
	if err := os.WriteFile(path, []byte("dirty-build-A"), 0o755); err != nil {
		t.Fatal(err)
	}
	dirty := domain.BuildInfo{Commit: "abc", Modified: true}
	w := newWatcher(path, dirty, func(string) (domain.BuildInfo, error) { return dirty, nil })

	replace(t, path, "dirty-build-A") // touched / reinstalled identical bytes
	if req, why := w.Check(); req {
		t.Fatalf("identical bytes must not need a restart: %s", why)
	}
	replace(t, path, "dirty-build-B") // same commit, dirty, different code
	if req, _ := w.Check(); !req {
		t.Fatal("different bytes of a dirty build must need a restart")
	}
}
