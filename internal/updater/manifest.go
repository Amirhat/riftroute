package updater

import (
	"os"
	"path/filepath"
)

// The newest verified release manifest, exactly as signed, is kept beside the
// update state: the desktop app installs its own update from it (it checks
// the signature again itself), and it survives a restart.
func manifestPath(dir string) string { return filepath.Join(dir, "update-manifest.json") }

// keepManifest records the manifest a check verified.
func (u *Updater) keepManifest(f fetched) {
	if len(f.raw) == 0 || len(f.sig) == 0 {
		return
	}
	if err := writeFileAtomic(manifestPath(u.env.StateDir)+".sig", f.sig, 0o644); err != nil {
		u.env.Log.Warn("can't keep the release manifest", "err", err)
		return
	}
	if err := writeFileAtomic(manifestPath(u.env.StateDir), f.raw, 0o644); err != nil {
		u.env.Log.Warn("can't keep the release manifest", "err", err)
	}
}

// Manifest returns the newest verified release manifest and its signature,
// as signed, or ok=false before the first successful check. Callers verify
// it themselves: it is only as good as its signature.
func (u *Updater) Manifest() (raw, sig []byte, ok bool) {
	raw, err1 := os.ReadFile(manifestPath(u.env.StateDir))
	sig, err2 := os.ReadFile(manifestPath(u.env.StateDir) + ".sig")
	if err1 != nil || err2 != nil || len(raw) == 0 || len(sig) == 0 {
		return nil, nil, false
	}
	return raw, sig, true
}
