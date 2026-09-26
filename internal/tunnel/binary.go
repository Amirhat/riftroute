package tunnel

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Amirhat/riftroute/internal/platform"
)

// Which openvpn the daemon runs as root, and the checks that make that safe.
//
// macOS: only the copy that ships with RiftRoute, installed root-owned beside
// the daemon (platform.InstalledOpenVPNPath). Never Homebrew's or MacPorts':
// their prefixes belong to the user who installed them, so any process
// running as that user could replace the binary — or a library or
// openssl.cnf it loads — and have the daemon run it as root. Never $PATH.
//
// Linux: the distribution's package, in the system directories. Not
// /usr/local, which some setups let a user write to.

// errNotFound means no openvpn binary is installed where the daemon looks.
var errNotFound = errors.New("openvpn not found")

// binaryCandidates are the only places the daemon runs openvpn from.
func binaryCandidates(goos string) []string {
	switch goos {
	case "darwin":
		if p := platform.InstalledOpenVPNPath(); p != "" {
			return []string{p}
		}
	case "linux":
		return []string{"/usr/sbin/openvpn", "/usr/bin/openvpn", "/sbin/openvpn"}
	}
	return nil
}

// lstatFunc is os.Lstat plus the file's owner. Tests replace it: they can't
// make root-owned files.
type lstatFunc func(path string) (fs.FileInfo, uint32, error)

// unsafeError is an openvpn the daemon won't run as root because someone
// other than root could have changed it, or could change what its path
// refers to.
type unsafeError struct {
	Bin  string // the openvpn (symlinks resolved)
	Path string // what failed: Bin itself or a directory above it
	Why  string // "isn't owned by root", "is writable by other users", …
}

func (e *unsafeError) Error() string {
	if e.Path == e.Bin {
		return fmt.Sprintf("%s %s, so RiftRoute won't run it as root", e.Bin, e.Why)
	}
	return fmt.Sprintf("the folder %s %s, so RiftRoute won't run %s as root", e.Path, e.Why, e.Bin)
}

// findOpenVPN returns the openvpn to run on this system — symlinks resolved,
// the file checked is the file to run — or errNotFound, or an *unsafeError.
func findOpenVPN() (string, fs.FileInfo, error) {
	return findIn(binaryCandidates(runtime.GOOS), lstatOwner)
}

// findIn returns the first candidate that exists. It is checked by
// rootOwned: a candidate that exists but isn't safe is reported, not skipped
// for the next one.
func findIn(candidates []string, lstat lstatFunc) (string, fs.FileInfo, error) {
	for _, p := range candidates {
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			continue // not there (or a dangling link)
		}
		if fi, err := os.Stat(real); err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
			continue // not a program
		}
		return rootOwned(real, lstat)
	}
	return "", nil, errNotFound
}

// rootOwned checks the file at real — a path with no symlinks left in it —
// and every directory above it, up to /: each must be owned by root and
// writable by no one else, and the file must be a regular file.
//
// Why this is enough to exec it as root afterwards (the time-of-check to
// time-of-use argument): replacing a file, or any directory on the way to it,
// or renaming something into its place, takes write permission on the
// directory that holds it. Every directory in the chain is root's and not
// group- or other-writable, so only root can change what real refers to
// between this check and the exec. (A sticky bit doesn't make a writable
// directory acceptable: it only stops users deleting each other's files, not
// creating a name that isn't there yet.) The resolved path is what gets
// executed, so the symlinks that led to it — and whoever can change them —
// no longer matter. Start also re-opens the file just before the exec and
// compares it with the one checked.
func rootOwned(real string, lstat lstatFunc) (string, fs.FileInfo, error) {
	if !filepath.IsAbs(real) {
		return "", nil, fmt.Errorf("%s isn't an absolute path", real)
	}
	fi, uid, err := lstat(real)
	if err != nil {
		return "", nil, err
	}
	if !fi.Mode().IsRegular() {
		return real, fi, &unsafeError{Bin: real, Path: real, Why: "isn't a regular file"}
	}
	if why := unsafeNode(fi, uid); why != "" {
		return real, fi, &unsafeError{Bin: real, Path: real, Why: why}
	}
	for dir := filepath.Dir(real); ; dir = filepath.Dir(dir) {
		dfi, duid, err := lstat(dir)
		if err != nil {
			return real, fi, err
		}
		if !dfi.IsDir() { // a symlink here appeared after EvalSymlinks
			return real, fi, &unsafeError{Bin: real, Path: dir, Why: "isn't a plain directory"}
		}
		if why := unsafeNode(dfi, duid); why != "" {
			return real, fi, &unsafeError{Bin: real, Path: dir, Why: why}
		}
		if parent := filepath.Dir(dir); parent == dir {
			break // checked /
		}
	}
	return real, fi, nil
}

// unsafeNode says why one file or directory could be changed by someone
// other than root, or "" when it can't.
func unsafeNode(fi fs.FileInfo, uid uint32) string {
	switch {
	case uid != 0:
		return "isn't owned by root"
	case fi.Mode().Perm()&0o022 != 0:
		return "is writable by other users"
	}
	return ""
}

// sameFileAsChecked opens bin and compares it (fstat) with the file rootOwned
// checked: the last look before the exec. By the argument on rootOwned, only
// root could have swapped it; this catches it if that happened anyway.
func sameFileAsChecked(bin string, checked fs.FileInfo) error {
	f, err := os.Open(bin)
	if err != nil {
		return fmt.Errorf("open openvpn: %w", err)
	}
	defer f.Close()
	now, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat openvpn: %w", err)
	}
	if !os.SameFile(now, checked) || now.Size() != checked.Size() || !now.ModTime().Equal(checked.ModTime()) {
		return fmt.Errorf("%s changed while it was being checked; not running it", bin)
	}
	return nil
}

// openvpnEnv is the whole environment openvpn runs with — as root, and as
// nobody for the version probe; nothing is inherited from the daemon.
//
//   - PATH: the system directories, for the ifconfig/route it execs
//     (script-security 1 allows only those).
//   - OPENSSL_CONF=/dev/null on macOS: the shipped openvpn's static OpenSSL
//     reads its config from a root-owned directory that doesn't exist, and
//     this makes sure no openssl.cnf — which can load providers — is ever
//     read. /dev/null rather than an empty file of our own: it always exists,
//     belongs to the OS (root), is always empty, and OpenSSL 3 loads it as an
//     empty configuration without complaint (the build script checks that
//     `openvpn --show-tls` runs cleanly with it). A file of our own would be
//     one more thing to install, check and keep empty.
//     Not on Linux: there the distribution's openssl.cnf is root's, and it is
//     where the system-wide crypto policy lives (RHEL/Fedora
//     crypto-policies, Debian's security level), which openvpn should obey.
func openvpnEnv(goos string) []string {
	env := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if goos == "darwin" {
		env = append(env, "OPENSSL_CONF=/dev/null")
	}
	return env
}
