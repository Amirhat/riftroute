package server

// Update channels (phase 2). Each channel is a signed manifest on disk —
// verified against the compiled-in release keys every time it's read, so a
// file swapped on the server is refused, not served — plus the admin's
// unsigned rollout advice in the database. Clients trust only the signature;
// the advice can hold an update back, never push one.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/Amirhat/riftroute/internal/update"
)

var reChannel = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func channelDir(dataDir, channel string) string {
	return filepath.Join(dataDir, "updates", channel)
}

// Channel is what the server knows about one channel.
type Channel struct {
	Name      string
	Manifest  update.Manifest
	KeyID     string
	Advice    update.Advice
	Published time.Time // when this manifest was published here
	raw, sig  []byte
}

// loadChannel reads and verifies a channel's manifest.
func loadChannel(dataDir, channel string, keys map[string]ed25519.PublicKey) (*Channel, error) {
	if !reChannel.MatchString(channel) {
		return nil, os.ErrNotExist
	}
	dir := channelDir(dataDir, channel)
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, "manifest.json.sig"))
	if err != nil {
		return nil, err
	}
	m, err := update.Verify(raw, sig, keys)
	if err != nil {
		return nil, fmt.Errorf("channel %s: %w", channel, err)
	}
	if m.Channel != channel {
		return nil, fmt.Errorf("channel %s holds a manifest for %q", channel, m.Channel)
	}
	var s update.Signature
	_ = json.Unmarshal(sig, &s)
	c := &Channel{Name: channel, Manifest: m, KeyID: s.KeyID, raw: raw, sig: sig}
	if fi, err := os.Stat(filepath.Join(dir, "manifest.json")); err == nil {
		c.Published = fi.ModTime()
	}
	return c, nil
}

// channels lists the channels that have a manifest (verified or not: an
// unverifiable one is shown to the admin with its error).
func (s *Server) channels() ([]*Channel, map[string]error) {
	entries, _ := os.ReadDir(filepath.Join(s.cfg.DataDir, "updates"))
	var out []*Channel
	errs := map[string]error{}
	for _, e := range entries {
		if !e.IsDir() || !reChannel.MatchString(e.Name()) {
			continue
		}
		c, err := loadChannel(s.cfg.DataDir, e.Name(), s.keys())
		if err != nil {
			errs[e.Name()] = err
			continue
		}
		adv, err := s.st.advice(e.Name())
		if err != nil {
			errs[e.Name()] = err
			continue
		}
		c.Advice = adv
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, errs
}

func (s *Server) keys() map[string]ed25519.PublicKey {
	if s.cfg.TrustedKeys != nil {
		return s.cfg.TrustedKeys
	}
	return update.TrustedKeys
}

// PublishManifest installs a signed manifest as a channel's current release
// (the `riftroute-server publish` command, run on the server as the service
// account). It refuses anything a client would refuse, a manifest for another
// channel, and a version older than the one already published; re-publishing
// the same version (e.g. to add an asset) is allowed and keeps its rollout and
// halt as they are. rollout sets a new version's starting percent (-1: 100);
// for the same version, -1 keeps the current advice.
func PublishManifest(dataDir, channel string, raw, sig []byte, rollout int, keys map[string]ed25519.PublicKey, now time.Time) (update.Manifest, error) {
	if keys == nil {
		keys = update.TrustedKeys
	}
	if !reChannel.MatchString(channel) {
		return update.Manifest{}, fmt.Errorf("channel %q invalid", channel)
	}
	if rollout < -1 || rollout > 100 {
		return update.Manifest{}, errors.New("rollout must be 0–100")
	}
	m, err := update.Verify(raw, sig, keys)
	if err != nil {
		return update.Manifest{}, err
	}
	if m.Channel != channel {
		return update.Manifest{}, fmt.Errorf("this manifest is for channel %q, not %q", m.Channel, channel)
	}
	sameVersion := false
	if cur, err := loadChannel(dataDir, channel, keys); err == nil {
		if update.Newer(m.Version, cur.Manifest.Version) {
			return update.Manifest{}, fmt.Errorf("%s is older than the published %s", m.Version, cur.Manifest.Version)
		}
		sameVersion = cur.Manifest.Version == m.Version
	}
	dir := channelDir(dataDir, channel)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return update.Manifest{}, err
	}
	// Signature first, then the manifest: a reader between the two renames
	// sees a mismatched pair and is refused, never a wrong-but-valid one.
	if err := writeAtomic(filepath.Join(dir, "manifest.json.sig"), sig); err != nil {
		return update.Manifest{}, err
	}
	if err := writeAtomic(filepath.Join(dir, "manifest.json"), raw); err != nil {
		return update.Manifest{}, err
	}
	if sameVersion && rollout == -1 {
		return m, nil // same release: its rollout and halt stay as they are
	}
	if rollout == -1 {
		rollout = 100
	}
	st, err := openStore(filepath.Join(dataDir, "server.db"))
	if err != nil {
		return m, fmt.Errorf("published, but setting the rollout failed: %w", err)
	}
	defer st.close()
	if err := st.setAdvice(channel, update.Advice{RolloutPercent: rollout}, now); err != nil {
		return m, fmt.Errorf("published, but setting the rollout failed: %w", err)
	}
	return m, nil
}

func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// updateResponse is what GET /api/v1/update/{channel} returns: the exact
// signed bytes (base64, so nothing re-encodes them) and the unsigned advice.
type updateResponse struct {
	Manifest  string        `json:"manifest"`
	Signature string        `json:"signature"`
	Advice    update.Advice `json:"advice"`
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	c, err := loadChannel(s.cfg.DataDir, r.PathValue("channel"), s.keys())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.cfg.Logger.Error("update channel unreadable", "channel", r.PathValue("channel"), "err", err)
		}
		// Short cache: a release published a moment later shows up soon.
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"no release on this channel"}` + "\n"))
		return
	}
	adv, err := s.st.advice(c.Name)
	if err != nil {
		// Fail closed: without the rollout advice, say nothing (clients then
		// go by the last advice they saw).
		s.cfg.Logger.Error("update advice unreadable", "channel", c.Name, "err", err)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"temporarily unavailable"}` + "\n"))
		return
	}
	// A minute of caching (Cloudflare and clients): a halt reaches everyone
	// within about a minute.
	w.Header().Set("Cache-Control", "public, max-age=60")
	_ = json.NewEncoder(w).Encode(updateResponse{
		Manifest:  base64.StdEncoding.EncodeToString(c.raw),
		Signature: base64.StdEncoding.EncodeToString(c.sig),
		Advice:    adv,
	})
}

// rolloutSteps are the percentages the admin page offers.
var rolloutSteps = []int{0, 5, 25, 50, 100}

func (s *Server) handleReleasesPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	_ = r.ParseForm()
	_, csrf, ok := s.sessionFrom(r)
	if !ok || !equalTokens(csrf, r.PostFormValue("csrf")) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	channel := r.PostFormValue("channel")
	if _, err := loadChannel(s.cfg.DataDir, channel, s.keys()); err != nil {
		http.Error(w, "unknown channel", http.StatusBadRequest)
		return
	}
	adv, err := s.st.advice(channel)
	if err != nil {
		s.cfg.Logger.Error("update advice unreadable", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	switch r.PostFormValue("action") {
	case "halt":
		adv.Halt = true
	case "resume":
		adv.Halt = false
	case "rollout":
		p, err := strconv.Atoi(r.PostFormValue("percent"))
		if err != nil || p < 0 || p > 100 {
			http.Error(w, "bad percent", http.StatusBadRequest)
			return
		}
		adv.RolloutPercent = p
	default:
		http.Error(w, "bad action", http.StatusBadRequest)
		return
	}
	if err := s.st.setAdvice(channel, adv, s.cfg.Now()); err != nil {
		s.cfg.Logger.Error("rollout change failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.cfg.Logger.Info("update rollout changed", "channel", channel, "percent", adv.RolloutPercent, "halt", adv.Halt)
	http.Redirect(w, r, "/admin#releases", http.StatusSeeOther)
}
