//go:build !windows

package tunnel

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/platform"
)

// modeInfo overrides a FileInfo's mode.
type modeInfo struct {
	fs.FileInfo
	mode fs.FileMode
}

func (m modeInfo) Mode() fs.FileMode { return m.mode }

// fakeFS stands in for a system tests can't build (they can't make files
// root's): real files under base, with owners from owners (root when not
// listed) and their real modes; everything above base looks like a clean
// system — root's, and writable by no one else (a test's temp dir may sit in
// a sticky, world-writable /tmp).
type fakeFS struct {
	base   string
	owners map[string]uint32
}

func newFakeFS(t *testing.T) *fakeFS {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir()) // macOS: /var → /private/var
	if err != nil {
		t.Fatal(err)
	}
	return &fakeFS{base: base, owners: map[string]uint32{}}
}

func (f *fakeFS) lstat(p string) (fs.FileInfo, uint32, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, 0, err
	}
	if p != f.base && !strings.HasPrefix(p, f.base+"/") {
		return modeInfo{fi, fi.Mode() &^ 0o022}, 0, nil
	}
	return fi, f.owners[p], nil
}

func (f *fakeFS) path(rel string) string { return filepath.Join(f.base, rel) }

func (f *fakeFS) file(t *testing.T, rel string, mode fs.FileMode) string {
	t.Helper()
	p := f.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // not umask's
		t.Fatal(err)
	}
	return p
}

func (f *fakeFS) chmod(t *testing.T, rel string, mode fs.FileMode) {
	t.Helper()
	if err := os.Chmod(f.path(rel), mode); err != nil {
		t.Fatal(err)
	}
}

func wantUnsafe(t *testing.T, err error, path, why string) {
	t.Helper()
	var u *unsafeError
	if !errors.As(err, &u) || u.Path != path || u.Why != why {
		t.Fatalf("want %s %q, got %v", path, why, err)
	}
}

func TestRootOwnedChainAccepted(t *testing.T) {
	f := newFakeFS(t)
	bin := f.file(t, "sbin/openvpn", 0o755)
	got, fi, err := findIn([]string{f.path("missing/openvpn"), bin}, f.lstat)
	if err != nil || got != bin || fi == nil || fi.Size() == 0 {
		t.Fatalf("got %q, %v, %v", got, fi, err)
	}
}

func TestLeafNotRootsIsRefused(t *testing.T) {
	f := newFakeFS(t)
	bin := f.file(t, "sbin/openvpn", 0o755)
	f.owners[bin] = 501
	_, _, err := findIn([]string{bin}, f.lstat)
	wantUnsafe(t, err, bin, "isn't owned by root")
	if !strings.Contains(err.Error(), "won't run it as root") {
		t.Fatalf("message: %v", err)
	}
}

func TestLeafWritableByOthersIsRefused(t *testing.T) {
	for _, mode := range []fs.FileMode{0o775, 0o757} {
		f := newFakeFS(t)
		bin := f.file(t, "sbin/openvpn", mode)
		_, _, err := findIn([]string{bin}, f.lstat)
		wantUnsafe(t, err, bin, "is writable by other users")
	}
}

// Any directory on the way, up to /, is part of the check: whoever can write
// to it can put another file in the binary's place.
func TestEveryParentDirectoryIsChecked(t *testing.T) {
	f := newFakeFS(t)
	bin := f.file(t, "a/b/sbin/openvpn", 0o755)
	f.owners[f.path("a")] = 501 // two levels up
	_, _, err := findIn([]string{bin}, f.lstat)
	wantUnsafe(t, err, f.path("a"), "isn't owned by root")
	if !strings.Contains(err.Error(), "the folder "+f.path("a")) {
		t.Fatalf("message: %v", err)
	}

	f = newFakeFS(t)
	bin = f.file(t, "a/b/sbin/openvpn", 0o755)
	f.chmod(t, "a/b", 0o775) // group-writable
	_, _, err = findIn([]string{bin}, f.lstat)
	wantUnsafe(t, err, f.path("a/b"), "is writable by other users")

	// The highest directory the test controls counts too.
	f = newFakeFS(t)
	bin = f.file(t, "sbin/openvpn", 0o755)
	f.owners[f.base] = 501
	_, _, err = findIn([]string{bin}, f.lstat)
	wantUnsafe(t, err, f.base, "isn't owned by root")
}

// A sticky bit limits deletes, not creating a name: /tmp-like directories
// don't qualify.
func TestStickyWorldWritableDirectoryIsRefused(t *testing.T) {
	f := newFakeFS(t)
	bin := f.file(t, "tmp/openvpn", 0o755)
	f.chmod(t, "tmp", 0o777|fs.ModeSticky)
	_, _, err := findIn([]string{bin}, f.lstat)
	wantUnsafe(t, err, f.path("tmp"), "is writable by other users")
}

// Symlinks are resolved first: the resolved file — and its directories — are
// what's checked and what runs; the link's own directory doesn't matter.
func TestSymlinksAreResolvedAndTheTargetChecked(t *testing.T) {
	f := newFakeFS(t)
	real := f.file(t, "usr/sbin/openvpn", 0o755)
	if err := os.MkdirAll(f.path("user/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.owners[f.path("user")] = 501 // the link lives in a user's directory
	link := f.path("user/bin/openvpn")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	got, _, err := findIn([]string{link}, f.lstat)
	if err != nil || got != real {
		t.Fatalf("got %q, %v; want the resolved %q", got, err, real)
	}

	// A root-owned link pointing into a user's directory is refused.
	f = newFakeFS(t)
	target := f.file(t, "home/me/openvpn", 0o755)
	f.owners[f.path("home/me")] = 501
	if err := os.MkdirAll(f.path("usr/sbin"), 0o755); err != nil {
		t.Fatal(err)
	}
	link = f.path("usr/sbin/openvpn")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, _, err = findIn([]string{link}, f.lstat)
	wantUnsafe(t, err, f.path("home/me"), "isn't owned by root")

	// A directory symlinked in the middle of the path (merged /usr: /sbin →
	// usr/sbin) resolves to the real directory.
	f = newFakeFS(t)
	real = f.file(t, "usr/sbin/openvpn", 0o755)
	if err := os.Symlink("usr/sbin", f.path("sbin")); err != nil {
		t.Fatal(err)
	}
	if got, _, err := findIn([]string{f.path("sbin/openvpn")}, f.lstat); err != nil || got != real {
		t.Fatalf("merged /usr: got %q, %v", got, err)
	}
}

func TestMissingOrNonProgramCandidatesAreSkipped(t *testing.T) {
	f := newFakeFS(t)
	if err := os.MkdirAll(f.path("a/openvpn"), 0o755); err != nil { // a directory
		t.Fatal(err)
	}
	noexec := f.file(t, "b/openvpn", 0o644)
	dangling := f.path("c/openvpn")
	if err := os.MkdirAll(filepath.Dir(dangling), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(f.path("nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, _, err := findIn([]string{f.path("a/openvpn"), noexec, dangling, f.path("d/openvpn")}, f.lstat); !errors.Is(err, errNotFound) {
		t.Fatalf("got %v", err)
	}
	// The first one that exists decides: an unsafe one is reported, not
	// passed over for a later candidate.
	bad := f.file(t, "e/openvpn", 0o777)
	good := f.file(t, "f/openvpn", 0o755)
	_, _, err := findIn([]string{bad, good}, f.lstat)
	wantUnsafe(t, err, bad, "is writable by other users")
}

// The owner check never guesses: a file whose owner can't be read isn't root's.
func TestLstatOwnerReadsTheRealOwner(t *testing.T) {
	p := t.TempDir() + "/f"
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, uid, err := lstatOwner(p)
	if err != nil || uid != uint32(os.Getuid()) {
		t.Fatalf("uid %d, %v; want %d", uid, err, os.Getuid())
	}
	if os.Getuid() != 0 {
		if _, _, err := rootOwned(p, lstatOwner); err == nil {
			t.Fatal("a file of this (non-root) user passed as root's")
		}
	}
}

func TestSameFileAsCheckedNoticesAReplacement(t *testing.T) {
	dir := t.TempDir()
	bin := dir + "/openvpn"
	if err := os.WriteFile(bin, []byte("one"), 0o755); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Lstat(bin)
	if err := sameFileAsChecked(bin, fi); err != nil {
		t.Fatalf("unchanged: %v", err)
	}
	if err := os.WriteFile(dir+"/other", []byte("two"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir+"/other", bin); err != nil {
		t.Fatal(err)
	}
	if err := sameFileAsChecked(bin, fi); err == nil {
		t.Fatal("a swapped binary went unnoticed")
	}
}

// Where the daemon looks: on macOS only RiftRoute's own copy; on Linux the
// system directories. Never a user-writable prefix.
func TestCandidatesAreSystemPathsOnly(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		for _, p := range binaryCandidates(goos) {
			for _, bad := range []string{"/opt/homebrew", "/usr/local", "/opt/local", "/Users", "/home"} {
				if strings.HasPrefix(p, bad) {
					t.Errorf("%s candidate %s is under %s", goos, p, bad)
				}
			}
		}
	}
	if got := binaryCandidates("linux"); strings.Join(got, " ") != "/usr/sbin/openvpn /usr/bin/openvpn /sbin/openvpn" {
		t.Errorf("linux: %v", got)
	}
	if runtime.GOOS == "darwin" {
		if got := binaryCandidates("darwin"); len(got) != 1 || got[0] != platform.InstalledOpenVPNPath() ||
			got[0] != "/Library/PrivilegedHelperTools/riftroute-openvpn" {
			t.Errorf("darwin: %v", got)
		}
	}
	if got := binaryCandidates("windows"); got != nil {
		t.Errorf("windows: %v", got)
	}
}

// readLines keeps reading past a line longer than any buffer: openvpn must
// never block writing its output (then Wait would never return).
func TestOutputReaderSurvivesAHugeLine(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	done := make(chan struct{})
	go func() {
		readLines(pr, 100, func(s string) { got = append(got, s) })
		close(done)
	}()
	huge := strings.Repeat("x", 1<<20) // far past a pipe buffer and a Scanner's 64 KiB
	wrote := make(chan error, 1)
	go func() {
		_, err := pw.WriteString("first\r\n" + huge + "\nafter the long line\nno newline at the end")
		pw.Close()
		wrote <- err
	}()
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the writer blocked: output stopped being read")
	}
	<-done
	if len(got) != 4 || got[0] != "first" || got[1] != strings.Repeat("x", 100) || got[2] != "after the long line" ||
		got[3] != "no newline at the end" {
		t.Fatalf("lines: %d %q", len(got), got[min(len(got), 2):])
	}
}
