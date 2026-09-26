package appupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/update"
)

type rewrite struct{ target *url.URL }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host = r.target.Scheme, r.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

// fakeInstaller records what it was asked to install.
type fakeInstaller struct {
	mu        sync.Mutex
	why       string
	installed []string // "version:content"
	err       error
	relaunch  string
	undone    int
}

func (f *fakeInstaller) Kind() string            { return "app-dmg" }
func (f *fakeInstaller) Arch() string            { return "universal" }
func (f *fakeInstaller) Check(string) string     { return f.why }
func (f *fakeInstaller) Relaunch(t string) error { f.relaunch = t; return nil }
func (f *fakeInstaller) Undo(string) error       { f.undone++; return nil }
func (f *fakeInstaller) Install(_ context.Context, artifact, _, version string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	b, _ := os.ReadFile(artifact)
	f.installed = append(f.installed, version+":"+string(b))
	return nil
}

type release struct {
	priv      ed25519.PrivateKey
	keys      map[string]ed25519.PublicKey
	dmg       []byte
	tamper    bool
	downloads int
	mu        sync.Mutex
	srv       *httptest.Server
}

func newRelease(t *testing.T) *release {
	pub, priv, _ := ed25519.GenerateKey(nil)
	r := &release{priv: priv, keys: map[string]ed25519.PublicKey{update.KeyID(pub): pub}, dmg: []byte("the 0.2.8 app")}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.downloads++
		b := r.dmg
		if r.tamper {
			b = []byte("something else entirely")
		}
		r.mu.Unlock()
		_, _ = w.Write(b)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *release) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.downloads
}

// signed returns a manifest for version (with the app's DMG), as signed.
func (r *release) signed(version string) ([]byte, []byte) {
	sum := sha256.Sum256(r.dmg)
	m := update.Manifest{Schema: 1, Channel: "stable", Version: version, Published: time.Unix(0, 0).UTC(),
		Assets: []update.ManifestAsset{
			{OS: "darwin", Arch: "universal", Kind: "app-dmg",
				URL:    "https://github.com/Amirhat/riftroute/releases/download/v" + version + "/RiftRoute_" + version + ".dmg",
				SHA256: hex.EncodeToString(sum[:]), Size: int64(len(r.dmg))},
			{OS: "darwin", Arch: "arm64", Kind: "tarball",
				URL:    "https://github.com/Amirhat/riftroute/releases/download/v" + version + "/riftroute_" + version + "_darwin_arm64.tar.gz",
				SHA256: hex.EncodeToString(sum[:]), Size: int64(len(r.dmg))},
		}}
	raw, _ := json.Marshal(m)
	sig, _ := json.Marshal(update.Sign(r.priv, raw))
	return raw, sig
}

func newUpdater(t *testing.T, r *release, current string, inst *fakeInstaller) *Updater {
	u, _ := url.Parse(r.srv.URL)
	return New(Env{
		Current: current, GOOS: "darwin", Keys: r.keys, HTTP: &http.Client{Transport: rewrite{u}},
		Target: "/Applications/RiftRoute.app", CacheDir: filepath.Join(t.TempDir(), "cache"), Installer: inst,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func daemonAt(version string, mode domain.UpdateMode) domain.UpdateStatus {
	return domain.UpdateStatus{Current: version, Mode: mode}
}

// Auto mode: once the daemon runs the new release, the app installs it and
// waits for a restart.
func TestAutoInstallsTheReleaseTheDaemonRuns(t *testing.T) {
	r := newRelease(t)
	inst := &fakeInstaller{}
	u := newUpdater(t, r, "0.2.7", inst)
	raw, sig := r.signed("0.2.8")
	st := u.Consider(context.Background(), daemonAt("0.2.8", domain.UpdateAuto), raw, sig)
	if st.State != StateReady || st.Target != "0.2.8" {
		t.Fatalf("status %+v", st)
	}
	if len(inst.installed) != 1 || inst.installed[0] != "0.2.8:the 0.2.8 app" {
		t.Fatalf("installed %q", inst.installed)
	}
	// Considered again, it doesn't reinstall.
	u.Consider(context.Background(), daemonAt("0.2.8", domain.UpdateAuto), raw, sig)
	if len(inst.installed) != 1 {
		t.Fatal("reinstalled")
	}
	if err := u.Relaunch(); err != nil || inst.relaunch != "/Applications/RiftRoute.app" {
		t.Fatalf("relaunch: %v %q", err, inst.relaunch)
	}
}

// The app follows the daemon: never ahead of it, never backwards, and not
// when updates are off.
func TestTheAppFollowsTheDaemon(t *testing.T) {
	r := newRelease(t)
	raw, sig := r.signed("0.2.8")
	for _, c := range []struct {
		name    string
		current string
		daemon  domain.UpdateStatus
	}{
		{"the daemon hasn't moved yet", "0.2.7", daemonAt("0.2.7", domain.UpdateAuto)},
		{"the daemon is still on probation", "0.2.7", domain.UpdateStatus{Current: "0.2.8", Mode: domain.UpdateAuto, Probation: true}},
		{"updates are off", "0.2.7", daemonAt("0.2.8", domain.UpdateOff)},
		{"the app is already there", "0.2.8", daemonAt("0.2.8", domain.UpdateAuto)},
		{"never backwards", "0.2.9", daemonAt("0.2.8", domain.UpdateAuto)},
	} {
		inst := &fakeInstaller{}
		st := newUpdater(t, r, c.current, inst).Consider(context.Background(), c.daemon, raw, sig)
		if st.State != StateIdle || len(inst.installed) != 0 {
			t.Errorf("%s: %+v, installed %q", c.name, st, inst.installed)
		}
	}
}

// Notify mode offers the release; the user's click installs it.
func TestNotifyWaitsForTheUser(t *testing.T) {
	r := newRelease(t)
	inst := &fakeInstaller{}
	u := newUpdater(t, r, "0.2.7", inst)
	raw, sig := r.signed("0.2.8")
	st := u.Consider(context.Background(), daemonAt("0.2.8", domain.UpdateNotify), raw, sig)
	if st.State != StateAvailable || st.Target != "0.2.8" || len(inst.installed) != 0 {
		t.Fatalf("status %+v, installed %q", st, inst.installed)
	}
	if st, err := u.Install(context.Background()); err != nil || st.State != StateReady {
		t.Fatalf("install: %+v %v", st, err)
	}
}

// Nothing unverified is used: a manifest signed by an unknown key, or a
// download that isn't the signed one.
func TestOnlyVerifiedReleasesAreInstalled(t *testing.T) {
	r := newRelease(t)
	inst := &fakeInstaller{}
	u := newUpdater(t, r, "0.2.7", inst)
	other := newRelease(t)
	raw, sig := other.signed("0.2.8") // a key the app doesn't trust
	if st := u.Consider(context.Background(), daemonAt("0.2.8", domain.UpdateAuto), raw, sig); st.State != StateIdle || len(inst.installed) != 0 {
		t.Fatalf("an untrusted manifest: %+v", st)
	}

	r.mu.Lock()
	r.tamper = true
	r.mu.Unlock()
	raw, sig = r.signed("0.2.8")
	st := u.Consider(context.Background(), daemonAt("0.2.8", domain.UpdateAuto), raw, sig)
	if st.State != StateError || len(inst.installed) != 0 {
		t.Fatalf("a tampered download: %+v", st)
	}
	// Not retried at every state push: after an hour, then two, …
	now := time.Now()
	u.env.Now = func() time.Time { return now }
	u.mu.Lock()
	f := u.failed["0.2.8"]
	f.at = now
	u.failed["0.2.8"] = f
	u.mu.Unlock()
	n := r.count()
	u.Consider(context.Background(), daemonAt("0.2.8", domain.UpdateAuto), raw, sig)
	if r.count() != n {
		t.Fatal("retried at once")
	}
	now = now.Add(61 * time.Minute)
	u.Consider(context.Background(), daemonAt("0.2.8", domain.UpdateAuto), raw, sig)
	if r.count() != n+1 {
		t.Fatal("not retried after an hour")
	}
	now = now.Add(61 * time.Minute) // the second failure waits two hours
	u.Consider(context.Background(), daemonAt("0.2.8", domain.UpdateAuto), raw, sig)
	if r.count() != n+1 {
		t.Fatal("retried an hour after the second failure")
	}
}

// The manifest the daemon serves is for the release it runs; one for any
// other release (a newer one held back) moves nothing.
func TestOnlyTheDaemonsOwnReleaseIsFollowed(t *testing.T) {
	r := newRelease(t)
	inst := &fakeInstaller{}
	raw, sig := r.signed("0.2.9")
	st := newUpdater(t, r, "0.2.7", inst).Consider(context.Background(), daemonAt("0.2.8", domain.UpdateAuto), raw, sig)
	if st.State != StateIdle || len(inst.installed) != 0 {
		t.Fatalf("%+v", st)
	}
}

// Once installed, nothing more happens in this process until the restart:
// a second swap would delete the bundle it runs from.
func TestReadyWaitsForTheRestart(t *testing.T) {
	r := newRelease(t)
	inst := &fakeInstaller{}
	u := newUpdater(t, r, "0.2.7", inst)
	raw, sig := r.signed("0.2.8")
	u.Consider(context.Background(), daemonAt("0.2.8", domain.UpdateAuto), raw, sig)
	raw9, sig9 := r.signed("0.2.9")
	st := u.Consider(context.Background(), daemonAt("0.2.9", domain.UpdateAuto), raw9, sig9)
	if st.State != StateReady || st.Target != "0.2.8" || len(inst.installed) != 1 {
		t.Fatalf("a second release before the restart: %+v, installed %q", st, inst.installed)
	}
	if st, err := u.Install(context.Background()); err != nil || len(inst.installed) != 1 || st.State != StateReady {
		t.Fatalf("a click while ready: %+v %v", st, err)
	}
}

// The daemon rejected the release (rolled back): the old app goes back
// before the user restarts into it.
func TestADaemonRollbackUndoesTheApp(t *testing.T) {
	r := newRelease(t)
	inst := &fakeInstaller{}
	u := newUpdater(t, r, "0.2.7", inst)
	raw, sig := r.signed("0.2.8")
	u.Consider(context.Background(), daemonAt("0.2.8", domain.UpdateAuto), raw, sig)
	st := u.Consider(context.Background(), domain.UpdateStatus{Current: "0.2.7", Mode: domain.UpdateAuto, RolledBackFrom: "0.2.8"}, nil, nil)
	if st.State != StateIdle || inst.undone != 1 {
		t.Fatalf("%+v, undone %d", st, inst.undone)
	}
	if err := u.Relaunch(); err == nil {
		t.Fatal("offered a restart into a rejected release")
	}
}

func TestUnsupportedAppsNeverTry(t *testing.T) {
	r := newRelease(t)
	raw, sig := r.signed("0.2.8")
	for _, c := range []struct {
		name, current string
		inst          *fakeInstaller
	}{
		{"development build", "0.2.7-3-gabc1234", &fakeInstaller{}},
		{"can't write where it's installed", "0.2.7", &fakeInstaller{why: "no write access"}},
	} {
		u := newUpdater(t, r, c.current, c.inst)
		st := u.Consider(context.Background(), daemonAt("0.2.8", domain.UpdateAuto), raw, sig)
		if st.State != StateUnsupported || st.Why == "" || len(c.inst.installed) != 0 {
			t.Errorf("%s: %+v", c.name, st)
		}
		// It still says a release is out (for a release build).
		if c.current == "0.2.7" && st.Target != "0.2.8" {
			t.Errorf("%s: the new release isn't mentioned: %+v", c.name, st)
		}
	}
}

func TestInstallErrorIsReported(t *testing.T) {
	r := newRelease(t)
	inst := &fakeInstaller{err: errors.New("disk full")}
	u := newUpdater(t, r, "0.2.7", inst)
	raw, sig := r.signed("0.2.8")
	st := u.Consider(context.Background(), daemonAt("0.2.8", domain.UpdateAuto), raw, sig)
	if st.State != StateError || st.Error != "disk full" {
		t.Fatalf("status %+v", st)
	}
	entries, _ := os.ReadDir(u.env.CacheDir)
	if len(entries) != 0 {
		t.Fatal("the download was left behind")
	}
}

// swap never leaves the app half-replaced.
func TestSwapKeepsThePreviousAppAndUndoesAFailure(t *testing.T) {
	dir := t.TempDir()
	target, next, prev := filepath.Join(dir, "RiftRoute.app"), filepath.Join(dir, ".new.app"), filepath.Join(dir, ".prev.app")
	mk := func(p, content string) {
		_ = os.MkdirAll(p, 0o755)
		_ = os.WriteFile(filepath.Join(p, "v"), []byte(content), 0o644)
	}
	read := func(p string) string { b, _ := os.ReadFile(filepath.Join(p, "v")); return string(b) }
	mk(target, "old")
	mk(next, "new")
	mk(prev, "older")
	if err := swap(next, target, prev); err != nil {
		t.Fatal(err)
	}
	if read(target) != "new" || read(prev) != "old" {
		t.Fatalf("target %q prev %q", read(target), read(prev))
	}
	// The new app went missing: the old one is put back.
	if err := swap(filepath.Join(dir, "missing.app"), target, prev); err == nil {
		t.Fatal("swapped in nothing")
	}
	if read(target) != "new" {
		t.Fatalf("the app wasn't put back: %q", read(target))
	}
}
