package updater

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Amirhat/riftroute/internal/update"
)

// fallbackGrace is how long a release only GitHub knows about (the update
// server couldn't be reached, and never gave its advice on this version)
// waits before it's installed from GitHub: time for the maintainer to halt
// it on the server or pull its manifest from the release.
var fallbackGrace = 7 * 24 * time.Hour

// errNotFound: a source answered, but has no release (404).
var errNotFound = errors.New("not found")

// errNoRelease: neither source has a signed release yet — not a failure.
var errNoRelease = errors.New("no signed release has been published yet")

type serverResponse struct {
	Manifest  string        `json:"manifest"`
	Signature string        `json:"signature"`
	Advice    update.Advice `json:"advice"`
}

// fetched is a verified manifest and what may hold it back.
type fetched struct {
	m      update.Manifest
	advice *update.Advice // nil: none known (GitHub, past its grace)
	source string         // "server" | "github"
	hold   string         // non-empty: hold back, and why (GitHub, within its grace)
}

// fetch returns a verified manifest: our server first (its advice is
// remembered), GitHub Releases if the server can't be reached. A GitHub copy
// obeys the server's last advice on that version; one the server never
// advised on waits out fallbackGrace. Nothing unverified is ever used.
func (u *Updater) fetch(ctx context.Context) (fetched, error) {
	m, adv, err := u.fromServer(ctx)
	if err == nil {
		_, _ = updateState(u.env.StateDir, func(ps *persisted) {
			ps.LastAdvice.Version, ps.LastAdvice.RolloutPercent, ps.LastAdvice.Halt, ps.LastAdvice.At =
				m.Version, adv.RolloutPercent, adv.Halt, u.env.Now()
		})
		return fetched{m: m, advice: &adv, source: "server"}, nil
	}
	u.env.Log.Info("update server unavailable; trying GitHub", "err", err)
	m2, err2 := u.fromGitHub(ctx)
	if err2 != nil {
		if errors.Is(err, errNotFound) && errors.Is(err2, errNotFound) {
			return fetched{}, errNoRelease
		}
		return fetched{}, fmt.Errorf("update server: %v; GitHub: %v", err, err2)
	}
	f := fetched{m: m2, source: "github"}
	ps, _ := loadPersisted(u.env.StateDir)
	switch {
	case ps.LastAdvice.Version == m2.Version:
		f.advice = &update.Advice{RolloutPercent: ps.LastAdvice.RolloutPercent, Halt: ps.LastAdvice.Halt}
	case u.env.Now().Sub(m2.Published) < fallbackGrace:
		f.hold = fmt.Sprintf("%s is out on GitHub, but the update server hasn't confirmed it yet; it installs from GitHub once it has been out for %d days",
			m2.Version, int(fallbackGrace/(24*time.Hour)))
	}
	return f, nil
}

func (u *Updater) fromServer(ctx context.Context) (update.Manifest, update.Advice, error) {
	b, err := u.get(ctx, u.env.ServerURL+u.env.Channel, 1<<20)
	if err != nil {
		return update.Manifest{}, update.Advice{}, err
	}
	var r serverResponse
	if err := json.Unmarshal(b, &r); err != nil {
		return update.Manifest{}, update.Advice{}, fmt.Errorf("server response: %w", err)
	}
	raw, err1 := base64.StdEncoding.DecodeString(r.Manifest)
	sig, err2 := base64.StdEncoding.DecodeString(r.Signature)
	if err1 != nil || err2 != nil {
		return update.Manifest{}, update.Advice{}, errors.New("server response: bad encoding")
	}
	m, err := u.verify(raw, sig)
	return m, r.Advice, err
}

func (u *Updater) fromGitHub(ctx context.Context) (update.Manifest, error) {
	raw, err := u.get(ctx, u.env.FallbackURL+"manifest.json", 1<<20)
	if err != nil {
		return update.Manifest{}, err
	}
	sig, err := u.get(ctx, u.env.FallbackURL+"manifest.json.sig", 64<<10)
	if err != nil {
		return update.Manifest{}, err
	}
	return u.verify(raw, sig)
}

func (u *Updater) verify(raw, sig []byte) (update.Manifest, error) {
	m, err := update.Verify(raw, sig, u.env.Keys)
	if err != nil {
		return m, err
	}
	if m.Channel != u.env.Channel {
		return m, fmt.Errorf("manifest is for channel %q, not %q", m.Channel, u.env.Channel)
	}
	return m, nil
}

// NewHTTPClient only ever talks HTTPS to the allow-listed hosts — every
// redirect hop included — and sends nothing that identifies the install.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if !update.AllowedAssetURL(req.URL.String()) {
				return fmt.Errorf("redirect to %s not allowed", req.URL.Host)
			}
			return nil
		},
	}
}

func (u *Updater) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	resp, err := u.open(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: response too large", url)
	}
	return b, nil
}

func (u *Updater) open(ctx context.Context, url string) (*http.Response, error) {
	if !update.AllowedAssetURL(url) {
		return nil, fmt.Errorf("%s: not an allowed update URL", url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "riftroute")
	resp, err := u.env.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return resp, nil
	case http.StatusNotFound:
		resp.Body.Close()
		return nil, fmt.Errorf("%s: %w", url, errNotFound)
	default:
		resp.Body.Close()
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
}
