package updater

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/update"
)

// staged is a verified, self-tested daemon waiting to be installed — with
// the openvpn from the same release, where one ships (macOS).
type staged struct {
	version  string
	path     string
	sum      string // sha256 of the binary at staging time, re-checked at swap
	raw, sig []byte // its release manifest as signed (kept at the swap)
	// openvpn is the release's openvpn ("" when this platform ships none or
	// the release doesn't include it: the installed one is left alone).
	openvpn    string
	openvpnSum string
}

// files are the staged files and the hashes they must still have at the swap.
func (s *staged) files() map[string]string {
	f := map[string]string{s.path: s.sum}
	if s.openvpn != "" {
		f[s.openvpn] = s.openvpnSum
	}
	return f
}

// Largest files the updater takes from a release tarball.
const (
	maxDaemonSize  = 150 << 20
	maxOpenVPNSize = 20 << 20 // a static openvpn is ~6 MB
)

// errBroken marks a problem with the release itself (as opposed to the
// network, the disk or a cancelled request): that release is skipped.
type errBroken struct{ err error }

func (e errBroken) Error() string { return e.err.Error() }
func (e errBroken) Unwrap() error { return e.err }

func broken(err error) error { return errBroken{err} }

// stage downloads the release tarball, checks it against the signed hash
// and size, unpacks the daemon (and, where one ships, openvpn) into a
// directory of its own, and self-tests them. A release that is itself broken
// is skipped until a newer one appears; anything else is retried at the next
// check.
func (u *Updater) stage(ctx context.Context, m update.Manifest) bool {
	u.mu.Lock()
	if s := u.staged; s != nil && s.version == m.Version && fileExists(s.path) && (s.openvpn == "" || fileExists(s.openvpn)) {
		u.mu.Unlock()
		return true
	}
	u.mu.Unlock()
	a, ok := m.Asset(u.env.GOOS, u.env.GOARCH, "tarball")
	if !ok {
		return false
	}
	u.dropStaged() // never leave a pointer at a file about to be replaced
	fail := func(err error) bool {
		var b errBroken
		skip := errors.As(err, &b) && ctx.Err() == nil
		u.env.Log.Warn("update staging failed", "version", m.Version, "err", err, "skipped", skip)
		msg := fmt.Sprintf("%s: %v", m.Version, err)
		if skip {
			msg += " — this release is skipped on this computer"
			_, _ = updateState(u.env.StateDir, func(ps *persisted) { ps.Skip = m.Version })
		}
		u.set(func(s *domain.UpdateStatus) { s.State, s.Error = "error", msg })
		_ = os.RemoveAll(stagingDir(u.env.StateDir))
		return false
	}
	dir := filepath.Join(stagingDir(u.env.StateDir), m.Version) // m.Version is a validated x.y.z
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail(err)
	}
	u.set(func(s *domain.UpdateStatus) { s.State = "downloading" })
	tgz := filepath.Join(dir, "release.tar.gz")
	if err := u.download(ctx, a, tgz); err != nil {
		return fail(err)
	}
	s := &staged{version: m.Version, path: filepath.Join(dir, "riftrouted")}
	if u.env.OpenVPN != "" {
		s.openvpn = filepath.Join(dir, "openvpn")
	}
	withOpenVPN, err := extractRelease(tgz, s.path, s.openvpn)
	if err != nil {
		return fail(err)
	}
	_ = os.Remove(tgz)
	if !withOpenVPN {
		if s.openvpn != "" {
			u.env.Log.Warn("update doesn't include openvpn; the installed one is kept", "version", m.Version)
		}
		s.openvpn = ""
	}
	if s.sum, err = fileSHA256(s.path); err != nil {
		return fail(err)
	}
	if s.openvpn != "" {
		if s.openvpnSum, err = fileSHA256(s.openvpn); err != nil {
			return fail(err)
		}
		if err := selfTestOpenVPN(ctx, s.openvpn); err != nil {
			return fail(err)
		}
	}
	if err := u.selfTest(ctx, s.path, m.Version); err != nil {
		return fail(err)
	}
	u.mu.Lock()
	u.staged = s
	u.mu.Unlock()
	u.set(func(s *domain.UpdateStatus) { s.State, s.Staged, s.Error = "waiting", m.Version, "" })
	u.env.Log.Info("update staged", "version", m.Version, "openvpn", s.openvpn != "")
	return true
}

// dropStaged forgets a staged update and deletes its files.
func (u *Updater) dropStaged() {
	u.mu.Lock()
	had := u.staged != nil
	u.staged = nil
	u.st.Staged = ""
	u.mu.Unlock()
	if had || fileExists(stagingDir(u.env.StateDir)) {
		_ = os.RemoveAll(stagingDir(u.env.StateDir))
	}
}

func (u *Updater) download(ctx context.Context, a update.ManifestAsset, dst string) error {
	resp, err := u.open(ctx, a.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, a.Size+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	// A short or altered download is a transfer problem, not the release's.
	if n != a.Size {
		return fmt.Errorf("download is %d bytes, the signed manifest says %d", n, a.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != a.SHA256 {
		return errors.New("download doesn't match the signed checksum")
	}
	return nil
}

// extractRelease pulls the files the updater installs out of the release
// tarball: riftrouted into daemonDst (required) and, when openvpnDst isn't
// "", openvpn into it (reporting whether the release has one). Anything that
// isn't a plain file of sane size, or appears twice, is refused. The tarball
// matched the signed hash, so a malformed one is the release's fault; a
// failed write is not.
func extractRelease(tgz, daemonDst, openvpnDst string) (bool, error) {
	f, err := os.Open(tgz)
	if err != nil {
		return false, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return false, broken(err)
	}
	type file struct {
		dst string
		max int64
	}
	want := map[string]file{"riftrouted": {daemonDst, maxDaemonSize}}
	if openvpnDst != "" {
		want["openvpn"] = file{openvpnDst, maxOpenVPNSize}
	}
	got := map[string]bool{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, broken(err)
		}
		name := strings.TrimPrefix(h.Name, "./")
		w, ok := want[name]
		if !ok {
			continue
		}
		if got[name] {
			return false, broken(fmt.Errorf("the release has %s twice", name))
		}
		if h.Typeflag != tar.TypeReg || h.Size <= 0 || h.Size > w.max {
			return false, broken(fmt.Errorf("%s in the release is not a plain file", name))
		}
		if err := writeLimited(w.dst, tr, h.Size); err != nil {
			return false, err
		}
		got[name] = true
	}
	if !got["riftrouted"] {
		return false, broken(errors.New("release has no riftrouted"))
	}
	return got["openvpn"], nil
}

func writeLimited(dst string, r io.Reader, n int64) error {
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, io.LimitReader(r, n)); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// selfTestOpenVPN runs the staged openvpn's --version, in the environment the
// daemon runs it with: a release whose openvpn doesn't run here (the wrong
// architecture, a missing library) is broken. It runs as root from the
// root-only staging dir; it matched the signed hash, like the daemon that
// selfTest runs.
func selfTestOpenVPN(ctx context.Context, bin string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--version")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "OPENSSL_CONF=/dev/null"}
	cmd.Dir = "/"
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.CombinedOutput() // some versions exit 1 after printing it
	if strings.HasPrefix(strings.TrimSpace(string(out)), "OpenVPN ") {
		return nil
	}
	if err == nil {
		return broken(fmt.Errorf("openvpn in the release doesn't say its version: %q", firstLine(out)))
	}
	return classifyRun(ctx, fmt.Errorf("openvpn --version: %w: %s", err, firstLine(out)))
}

func firstLine(b []byte) string {
	l, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	return l
}

// selfTest runs the staged binary: its version must be the manifest's, and
// `riftrouted -selftest` (with the running service's own arguments) must
// open a copy of the live database, migrate it and initialise the provider.
// Only a binary that runs and fails is the release's fault.
func (u *Updater) selfTest(ctx context.Context, bin, version string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-version").Output()
	if err != nil {
		return classifyRun(ctx, fmt.Errorf("%s -version: %w", filepath.Base(bin), err))
	}
	if got := strings.Fields(string(out)); len(got) == 0 || strings.TrimPrefix(got[0], "v") != version {
		return broken(fmt.Errorf("the binary says it is %q, the manifest says %s", strings.TrimSpace(string(out)), version))
	}
	if u.env.SelfTest == nil {
		return nil
	}
	db := filepath.Join(filepath.Dir(bin), "selftest.db")
	_ = os.Remove(db)
	defer os.Remove(db)
	if err := u.env.BackupDB(db); err != nil {
		return fmt.Errorf("copy database: %w", err)
	}
	if err := u.env.SelfTest(ctx, bin, db); err != nil {
		return classifyRun(ctx, fmt.Errorf("self-test failed: %w", err))
	}
	return nil
}

// classifyRun: the binary ran and failed, or isn't an executable for this
// machine (notExecutable: the wrong architecture or format) → the release is
// broken. Anything else — cancelled or timed out, out of memory or processes
// (EAGAIN, ENOMEM), a busy or unexecutable file system (ETXTBSY, EACCES), a
// missing file — is this computer's moment, not the release's.
func classifyRun(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return err
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return broken(err)
	}
	for _, errno := range notExecutable {
		if errors.Is(err, errno) {
			return broken(err)
		}
	}
	return err
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
