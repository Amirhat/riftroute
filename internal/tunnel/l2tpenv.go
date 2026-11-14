package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/ipsec"
	"github.com/Amirhat/riftroute/internal/platform"
)

// SystemL2TP is L2TP/IPsec's environment here: this OS's TUN, and IPsec by
// the charon that ships with RiftRoute (macOS) or the distribution's
// charon-systemd (Linux; it writes no PID file, so it runs beside a system
// strongSwan). One charon carries every tunnel's IPsec.
func SystemL2TP(log *slog.Logger) *L2TPEnv {
	r := &charonRunner{log: log}
	return &L2TPEnv{IPsec: r, IPsecEngine: r.Engine}
}

// charonCandidates are the only places the daemon runs charon from.
func charonCandidates(goos string) []string {
	switch goos {
	case "darwin":
		if p := platform.InstalledCharonPath(); p != "" {
			return []string{p}
		}
	case "linux":
		return []string{"/usr/sbin/charon-systemd", "/usr/libexec/strongswan/charon-systemd", "/usr/lib/strongswan/charon-systemd"}
	}
	return nil
}

// charonDir is its run directory: the shipped charon's PID directory
// (macOS), or one of RiftRoute's own.
func charonDir(goos string) string {
	if d := platform.CharonRunDir(); d != "" {
		return d
	}
	return "/run/riftroute-ipsec"
}

// charonRunner runs the one charon (ipsec.Charon), from the binary the
// engine checks, every time it starts.
type charonRunner struct {
	log *slog.Logger
	vc  versionCache

	mu sync.Mutex
	ch *ipsec.Charon
	n  int // connections up
}

// Engine reports whether charon can run L2TP/IPsec here.
func (r *charonRunner) Engine() domain.TunnelEngine {
	e, _ := r.engine()
	return e
}

func (r *charonRunner) engine() (domain.TunnelEngine, fs.FileInfo) {
	h := readHost()
	if !supportedOS(h.goos) {
		return domain.TunnelEngine{Problem: "L2TP/IPsec tunnels aren't supported on " + h.goos}, nil
	}
	bin, fi, err := findIn(charonCandidates(h.goos), lstatOwner)
	switch {
	case errors.Is(err, errNotFound):
		return domain.TunnelEngine{Problem: "strongSwan's charon isn't installed", Install: charonHelp(h, true)}, nil
	case err != nil:
		return domain.TunnelEngine{Path: bin, Problem: err.Error(), Install: charonHelp(h, false)}, nil
	}
	e := domain.TunnelEngine{Path: bin, Available: true, Version: "charon-systemd"}
	if h.goos == "darwin" {
		// charon-systemd takes no arguments (--version would start it); the
		// shipped charon says its version.
		if e.Version, err = r.vc.versionBy(bin, fi, probeCharonVersion); err != nil {
			return domain.TunnelEngine{Path: bin, Problem: err.Error(), Install: charonHelp(h, false)}, fi
		}
	}
	return e, fi
}

// probeCharonVersion runs `charon --version` as nobody, with an empty
// strongswan.conf (charon reads one first, and takes /dev/null for an
// invalid one).
func probeCharonVersion(bin string) (string, error) {
	dir, err := os.MkdirTemp("", "rr-charon-version")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	conf := filepath.Join(dir, "strongswan.conf")
	if err := os.WriteFile(conf, nil, 0o644); err != nil {
		return "", err
	}
	_ = os.Chmod(dir, 0o755) // nobody reads it
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--version")
	cmd.Env = append(openvpnEnv(runtime.GOOS), "STRONGSWAN_CONF="+conf)
	cmd.Dir = "/"
	cmd.WaitDelay = 2 * time.Second
	unprivileged(cmd)
	out, err := cmd.CombinedOutput()
	if m := reIKEVersion.FindSubmatch(out); m != nil {
		return strings.TrimPrefix(string(m[0]), "strongSwan "), nil
	}
	if err != nil {
		return "", fmt.Errorf("%s doesn't run: %s", bin, firstLine(out, err))
	}
	return "", fmt.Errorf("%s --version didn't say which strongSwan it is", bin)
}

const (
	charonMacUpdate = "L2TP/IPsec tunnels use the strongSwan charon that ships with RiftRoute (0.10 and newer). Checking for " +
		"updates installs it: `riftroute update check`, or Check for updates on the app's Tunnels page. Reinstalling the " +
		"daemon from a current release (`sudo riftroute daemon install`) also puts it in place."
	charonLinuxNote = "Install strongSwan's charon-systemd with its openssl, kernel-netlink and vici plugins, from your " +
		"distribution's packages."
)

// charonLinuxInstall: what installs charon-systemd and the plugins it loads.
var charonLinuxInstall = []struct {
	ids                []string
	install, reinstall string
}{
	// vici is in swanctl's package, OpenSSL's crypto in the standard plugins.
	{ids: []string{"debian", "ubuntu"},
		install:   "sudo apt install --no-install-recommends charon-systemd strongswan-swanctl libstrongswan-standard-plugins",
		reinstall: "sudo apt install --reinstall --no-install-recommends charon-systemd strongswan-swanctl libstrongswan-standard-plugins"},
	{ids: []string{"fedora", "rhel", "rocky", "almalinux", "centos"}, install: "sudo dnf install strongswan", reinstall: "sudo dnf reinstall strongswan"},
	{ids: []string{"arch"}, install: "sudo pacman -S strongswan", reinstall: "sudo pacman -S strongswan"},
	{ids: []string{"opensuse", "opensuse-leap", "opensuse-tumbleweed", "suse", "sles"}, install: "sudo zypper install strongswan",
		reinstall: "sudo zypper install --force strongswan"},
}

func charonHelp(h hostInfo, missing bool) *domain.TunnelInstall {
	in := newHelp(h, missing)
	switch h.goos {
	case "darwin":
		in.Note, in.URL = charonMacUpdate, releasesURL
	case "linux":
		ids := append([]string{h.osRelease["ID"]}, strings.Fields(h.osRelease["ID_LIKE"])...)
		for _, id := range ids {
			for _, d := range charonLinuxInstall {
				if id != "" && slices.Contains(d.ids, id) {
					in.Commands = []string{d.reinstall}
					if missing {
						in.Commands = []string{d.install}
					}
					return in
				}
			}
		}
		in.Note = charonLinuxNote
	}
	return in
}

// Up starts charon if it isn't running (from the binary just checked) and
// brings the connection up.
func (r *charonRunner) Up(ctx context.Context, c ipsec.Conn) error {
	e, fi := r.engine()
	if !e.Available {
		return &EngineError{Engine: e}
	}
	if err := sameFileAsChecked(e.Path, fi); err != nil {
		return err
	}
	r.mu.Lock()
	if r.ch == nil || r.ch.Bin != e.Path {
		if r.ch != nil {
			r.ch.Stop()
		}
		r.ch = &ipsec.Charon{
			Bin: e.Path, Dir: charonDir(runtime.GOOS), GOOS: runtime.GOOS, Log: r.log.With("ipsec", "charon"),
			Env: openvpnEnv(runtime.GOOS),
			// Its own session (a terminal's signals don't reach it); on Linux it
			// ends with the daemon, which deletes its SAs and policies.
			Prepare: ownSession,
		}
	}
	ch := r.ch
	r.mu.Unlock()
	return ch.Up(ctx, c)
}

// Down takes a connection down; the last one stops charon.
func (r *charonRunner) Down(name string) {
	r.mu.Lock()
	ch := r.ch
	r.mu.Unlock()
	if ch != nil {
		ch.Down(name)
	}
}

// Stop ends charon (the daemon shutting down).
func (r *charonRunner) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ch != nil {
		r.ch.Stop()
	}
}
