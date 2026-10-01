package updater

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"

	"github.com/Amirhat/riftroute/internal/update"
)

// repairHelpers installs the helpers RiftRoute ships (openvpn, charon-cmd)
// that are missing. An update applied by an older updater — one that knew
// only about the daemon, or not about this helper — leaves it out, and the
// tunnels it runs can't start without it. It comes from m, the newest signed
// release the check fetched, even when the daemon isn't updating to it (a
// rollout, a halt, a Skip or updates off hold it back): every helper
// RiftRoute ships runs every daemon's tunnels. Only the helpers are taken,
// never the daemon, with the same checks as an update (signed hash and size,
// a plain file, a self-test); a release whose helper can't be installed for
// good (it ships none, or one that doesn't run here) is tried once for it.
// Runs inside a job (holding u.busy).
func (u *Updater) repairHelpers(ctx context.Context, m update.Manifest) {
	var missing []helper
	for _, h := range u.helpers() {
		if !fileExists(h.path) {
			missing = append(missing, h)
		}
	}
	if len(missing) == 0 || !u.env.SelfUpdatable {
		return
	}
	ps, _ := loadPersisted(u.env.StateDir)
	missing = slices.DeleteFunc(missing, func(h helper) bool { return ps.repairOf(h.name) == m.Version })
	if len(missing) == 0 {
		return
	}
	if _, onProbation := readMarker(u.env.StateDir); onProbation {
		return // let the update settle (or roll back) first
	}
	a, ok := m.Asset(u.env.GOOS, u.env.GOARCH, "tarball")
	if !ok {
		return
	}

	giveUp := func(h helper, why string) {
		u.env.Log.Warn("can't install the "+h.name+" a release ships", "release", m.Version, "running", u.env.Current, "why", why)
		u.save(func(ps *persisted) { ps.setRepair(h.name, m.Version) })
	}
	dir := filepath.Join(stagingDir(u.env.StateDir), "repair")
	_ = os.RemoveAll(dir)
	defer os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	tgz := filepath.Join(dir, "release.tar.gz")
	if err := u.download(ctx, a, tgz); err != nil {
		u.env.Log.Warn("helper repair: download failed; trying again at the next check", "err", err)
		return
	}
	got, err := extractRelease(tgz, filepath.Join(dir, "riftrouted"), dir, missing)
	var b errBroken
	switch {
	case errors.As(err, &b):
		for _, h := range missing {
			giveUp(h, err.Error())
		}
		return
	case err != nil:
		return
	}
	for _, h := range missing {
		bin := filepath.Join(dir, h.name)
		if !got[h.name] {
			giveUp(h, "the release doesn't include "+h.name)
			continue
		}
		if err := selfTestHelper(ctx, h, bin); err != nil {
			if errors.As(err, &b) {
				giveUp(h, err.Error())
			}
			continue
		}
		if err := copyFileAtomic(bin, h.path, 0o755); err != nil {
			u.env.Log.Warn(h.name+" repair: install failed", "err", err)
			continue
		}
		u.env.Log.Info("installed the "+h.name+" RiftRoute ships", "release", m.Version, "running", u.env.Current, "path", h.path)
	}
}
