package updater

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// signedManifest is a release manifest exactly as signed, with its
// signature, kept in one file (written atomically, so a reader never pairs a
// manifest with another's signature).
type signedManifest struct {
	Version   string `json:"version"`
	Manifest  []byte `json:"manifest"`
	Signature []byte `json:"signature"`
}

// The desktop app installs its own update from the manifest of the release
// this daemon runs, so that one is kept apart from the newest a check
// verified — they differ while a newer release is held back (a rollout, a
// halt, notify mode, a skip):
//   - latest: the newest release a check verified;
//   - running: the release this daemon was updated to (written at the swap);
//   - previous: the running one before that, for after a rollback.
func manifestPath(dir, which string) string {
	return filepath.Join(dir, "update-manifest-"+which+".json")
}

func writeManifest(path string, sm signedManifest) error {
	b, err := json.Marshal(sm)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0o644)
}

func readManifest(path string) (signedManifest, bool) {
	var sm signedManifest
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &sm) != nil || len(sm.Manifest) == 0 || len(sm.Signature) == 0 {
		return signedManifest{}, false
	}
	return sm, true
}

// keepManifest records the manifest a check verified: always as the latest,
// and as the running one too when it is this daemon's own release (a daemon
// installed by hand learns its release's manifest that way).
func (u *Updater) keepManifest(f fetched) {
	if len(f.raw) == 0 || len(f.sig) == 0 {
		return
	}
	sm := signedManifest{Version: f.m.Version, Manifest: f.raw, Signature: f.sig}
	if err := writeManifest(manifestPath(u.env.StateDir, "latest"), sm); err != nil {
		u.env.Log.Warn("can't keep the release manifest", "err", err)
	}
	if f.m.Version == u.env.Current {
		if err := writeManifest(manifestPath(u.env.StateDir, "running"), sm); err != nil {
			u.env.Log.Warn("can't keep the release manifest", "err", err)
		}
	}
}

// keepRunningManifest is the swap's: the release being installed becomes the
// running one, and the running one the previous.
func (u *Updater) keepRunningManifest(s *staged) {
	if len(s.raw) == 0 {
		return
	}
	dir := u.env.StateDir
	if cur, ok := readManifest(manifestPath(dir, "running")); ok && cur.Version != s.version {
		_ = writeManifest(manifestPath(dir, "previous"), cur)
	}
	if err := writeManifest(manifestPath(dir, "running"), signedManifest{Version: s.version, Manifest: s.raw, Signature: s.sig}); err != nil {
		u.env.Log.Warn("can't keep the release manifest", "err", err)
	}
}

// Manifest returns the manifest of the release this daemon runs, as signed,
// with its signature — ok=false while it isn't known. Callers verify it
// themselves: it is only as good as its signature.
func (u *Updater) Manifest() (raw, sig []byte, ok bool) {
	for _, which := range []string{"running", "previous", "latest"} {
		if sm, ok := readManifest(manifestPath(u.env.StateDir, which)); ok && sm.Version == u.env.Current {
			return sm.Manifest, sm.Signature, true
		}
	}
	return nil, nil, false
}
