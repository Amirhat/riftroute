package updater

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/Amirhat/riftroute/internal/update"
)

// repairOpenVPN installs the openvpn the running release ships with when it's
// missing. An update applied by an older updater — one that knew only about
// the daemon — leaves it out, and macOS tunnels can't run without it. Only
// the running version's own signed release is used: the same checks as an
// update (signed hash and size, a plain file, a self-test), and the openvpn
// that belongs with this daemon rather than a newer one. Runs inside a job
// (holding u.busy).
func (u *Updater) repairOpenVPN(ctx context.Context, m update.Manifest) {
	if u.env.OpenVPN == "" || fileExists(u.env.OpenVPN) || !u.env.SelfUpdatable {
		return
	}
	if ps, _ := loadPersisted(u.env.StateDir); ps.OpenVPNRepair == m.Version {
		return
	}
	if _, onProbation := readMarker(u.env.StateDir); onProbation {
		return // let the update settle (or roll back) first
	}
	a, ok := m.Asset(u.env.GOOS, u.env.GOARCH, "tarball")
	if !ok {
		return
	}

	giveUp := func(why string) {
		u.env.Log.Warn("can't install the openvpn this release ships with", "version", m.Version, "why", why)
		u.save(func(ps *persisted) { ps.OpenVPNRepair = m.Version })
	}
	dir := filepath.Join(stagingDir(u.env.StateDir), "repair")
	_ = os.RemoveAll(dir)
	defer os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	tgz := filepath.Join(dir, "release.tar.gz")
	if err := u.download(ctx, a, tgz); err != nil {
		u.env.Log.Warn("openvpn repair: download failed; trying again at the next check", "err", err)
		return
	}
	bin := filepath.Join(dir, "openvpn")
	has, err := extractRelease(tgz, filepath.Join(dir, "riftrouted"), bin)
	var b errBroken
	switch {
	case errors.As(err, &b):
		giveUp(err.Error())
		return
	case err != nil:
		return
	case !has:
		giveUp("the release doesn't include openvpn")
		return
	}
	if err := selfTestOpenVPN(ctx, bin); err != nil {
		if errors.As(err, &b) {
			giveUp(err.Error())
		}
		return
	}
	if err := copyFileAtomic(bin, u.env.OpenVPN, 0o755); err != nil {
		u.env.Log.Warn("openvpn repair: install failed", "err", err)
		return
	}
	u.env.Log.Info("installed the openvpn this release ships with", "version", m.Version, "path", u.env.OpenVPN)
}
