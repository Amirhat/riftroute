package update

// Signed update manifests (phase 2). A release reaches users only through a
// manifest signed with a key that lives on the maintainer's machine; the
// public half is compiled in (keys.go). Where the manifest came from — our
// server, GitHub, a cache — doesn't matter: the signature is the only thing
// trusted. Unsigned advice from the server (rollout percent, halt) can only
// hold an update back, never deliver one.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ManifestSchema is the manifest format version this build understands.
const ManifestSchema = 1

// MaxAssetSize bounds any single download (the tarballs are ~15 MB).
const MaxAssetSize = 200 << 20

// Manifest describes one signed release on one channel.
type Manifest struct {
	Schema    int             `json:"schema"`
	Channel   string          `json:"channel"`
	Version   string          `json:"version"`
	Published time.Time       `json:"published"`
	NotesURL  string          `json:"notes_url,omitempty"`
	MinFrom   string          `json:"min_from,omitempty"` // older installs: notify only
	Assets    []ManifestAsset `json:"assets"`
}

// ManifestAsset is one downloadable file, pinned by hash and size.
type ManifestAsset struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Kind   string `json:"kind"` // "tarball" (CLI + daemon); others are notify-only
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Signature is the detached signature file published next to a manifest
// (manifest.json.sig): an ed25519 signature over the exact manifest bytes.
type Signature struct {
	KeyID string `json:"key_id"`
	Alg   string `json:"alg"`
	Sig   string `json:"sig"` // base64 (std)
}

// Advice is the server's unsigned rollout control. It is applied only to
// hold an update back.
type Advice struct {
	RolloutPercent int  `json:"rollout_percent"`
	Halt           bool `json:"halt"`
}

// KeyID names a public key: "rr-" + the first 8 bytes of its SHA-256, hex.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "rr-" + hex.EncodeToString(sum[:8])
}

// Sign signs manifest bytes (release tooling only; the private key never
// leaves the maintainer's machine).
func Sign(priv ed25519.PrivateKey, manifest []byte) Signature {
	return Signature{
		KeyID: KeyID(priv.Public().(ed25519.PublicKey)),
		Alg:   "ed25519",
		Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(priv, manifest)),
	}
}

// Errors a caller may want to tell apart.
var (
	ErrUnknownKey   = errors.New("manifest signed by an unknown key")
	ErrBadSignature = errors.New("manifest signature does not verify")
)

// Verify checks sig over the exact manifest bytes against the trusted keys,
// then parses and validates the manifest. Nothing in an unverified manifest
// is looked at.
func Verify(manifest, sig []byte, trusted map[string]ed25519.PublicKey) (Manifest, error) {
	var s Signature
	if err := json.Unmarshal(sig, &s); err != nil {
		return Manifest{}, fmt.Errorf("signature file: %w", err)
	}
	if s.Alg != "ed25519" {
		return Manifest{}, fmt.Errorf("signature algorithm %q not supported", s.Alg)
	}
	pub, ok := trusted[s.KeyID]
	if !ok {
		return Manifest{}, fmt.Errorf("%w (%s)", ErrUnknownKey, s.KeyID)
	}
	raw, err := base64.StdEncoding.DecodeString(s.Sig)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return Manifest{}, ErrBadSignature
	}
	if !ed25519.Verify(pub, manifest, raw) {
		return Manifest{}, ErrBadSignature
	}
	var m Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return Manifest{}, fmt.Errorf("manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

var (
	reSHA256  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reChannel = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
)

// assetHosts are the only places a manifest may send the updater. GitHub's
// download URLs redirect to its object storage; the HTTP client re-checks
// every hop against this list.
var assetHosts = map[string]bool{
	"github.com":                           true,
	"objects.githubusercontent.com":        true,
	"release-assets.githubusercontent.com": true,
	"riftroute.tellnew.tech":               true,
}

// AllowedAssetURL reports whether u may be fetched for a release asset.
func AllowedAssetURL(u string) bool {
	p, err := url.Parse(u)
	return err == nil && p.Scheme == "https" && p.User == nil && assetHosts[strings.ToLower(p.Hostname())] && p.Port() == ""
}

// Validate rejects a manifest this build can't safely act on.
func (m Manifest) Validate() error {
	if m.Schema != ManifestSchema {
		return fmt.Errorf("manifest schema %d not supported (want %d)", m.Schema, ManifestSchema)
	}
	if !reChannel.MatchString(m.Channel) {
		return fmt.Errorf("manifest channel %q invalid", m.Channel)
	}
	if !IsRelease(m.Version) {
		return fmt.Errorf("manifest version %q is not a release version", m.Version)
	}
	if m.MinFrom != "" && !IsRelease(m.MinFrom) {
		return fmt.Errorf("manifest min_from %q invalid", m.MinFrom)
	}
	if len(m.Assets) == 0 {
		return errors.New("manifest lists no assets")
	}
	seen := map[string]bool{}
	for _, a := range m.Assets {
		k := a.OS + "/" + a.Arch + "/" + a.Kind
		switch {
		case a.OS == "" || a.Arch == "" || a.Kind == "":
			return fmt.Errorf("manifest asset %q: os, arch and kind are required", a.URL)
		case seen[k]:
			return fmt.Errorf("manifest lists %s twice", k)
		case !AllowedAssetURL(a.URL):
			return fmt.Errorf("manifest asset URL %q not allowed", a.URL)
		case !reSHA256.MatchString(a.SHA256):
			return fmt.Errorf("manifest asset %s: bad sha256", k)
		case a.Size <= 0 || a.Size > MaxAssetSize:
			return fmt.Errorf("manifest asset %s: size %d out of range", k, a.Size)
		}
		seen[k] = true
	}
	return nil
}

// Asset returns the asset for a platform and kind.
func (m Manifest) Asset(goos, goarch, kind string) (ManifestAsset, bool) {
	for _, a := range m.Assets {
		if a.OS == goos && a.Arch == goarch && a.Kind == kind {
			return a, true
		}
	}
	return ManifestAsset{}, false
}

// IsRelease reports whether v is a plain release version (x.y.z, optional
// leading v) — no pre-release or build suffix. Dev builds such as
// "0.2.4-8-gd4501c1" are never updated automatically.
func IsRelease(v string) bool {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if strings.ContainsAny(v, "-+") {
		return false
	}
	_, ok := parseSemver(v)
	return ok
}

// Action is what the updater should do with a verified manifest.
type Action string

const (
	ActionNone    Action = "none"    // nothing newer (or not for us)
	ActionHold    Action = "hold"    // newer, but held back (rollout, halt)
	ActionNotify  Action = "notify"  // newer: tell the user, don't install
	ActionInstall Action = "install" // newer: install it
)

// Decision explains an Action in words a person can read.
type Decision struct {
	Action Action `json:"action"`
	Reason string `json:"reason"`
}

// DecideInput is everything Decide needs; it does no I/O.
type DecideInput struct {
	Current  string // running version
	Mode     string // preference: "auto" | "notify" | "off"
	Manifest Manifest
	Advice   *Advice // nil when the manifest came from the fallback
	Bucket   int     // this install's rollout bucket, 0–99
	GOOS     string
	GOARCH   string
	// SelfUpdatable is false where the updater must not replace files:
	// package-managed installs (.deb), a daemon not running as a service.
	SelfUpdatable bool
	// Skip is a version this install rolled back from; it is never offered
	// again (a newer one is).
	Skip string
}

// Decide applies the update rules. Order matters: a newer version is
// required first; then the server's halt and rollout can only hold it back;
// then the preference and the install's situation decide notify vs install.
func Decide(in DecideInput) Decision {
	m := in.Manifest
	if in.Mode == "off" {
		return Decision{ActionNone, "updates are off"}
	}
	if !Newer(in.Current, m.Version) {
		return Decision{ActionNone, "up to date"}
	}
	if in.Skip != "" && !Newer(in.Skip, m.Version) {
		return Decision{ActionNone, fmt.Sprintf("%s was rolled back on this computer", m.Version)}
	}
	if in.Advice != nil {
		if in.Advice.Halt {
			return Decision{ActionHold, "the rollout of " + m.Version + " is paused"}
		}
		if in.Bucket >= clampPercent(in.Advice.RolloutPercent) {
			return Decision{ActionHold, fmt.Sprintf("%s is rolling out gradually (%d%%)", m.Version, clampPercent(in.Advice.RolloutPercent))}
		}
	}
	if _, ok := m.Asset(in.GOOS, in.GOARCH, "tarball"); !ok {
		return Decision{ActionNotify, fmt.Sprintf("%s is available (no automatic install for %s/%s)", m.Version, in.GOOS, in.GOARCH)}
	}
	switch {
	case in.Mode != "auto":
		return Decision{ActionNotify, m.Version + " is available"}
	case !IsRelease(in.Current):
		return Decision{ActionNotify, m.Version + " is available (this is a development build; install it yourself)"}
	case !in.SelfUpdatable:
		return Decision{ActionNotify, m.Version + " is available (this install is managed elsewhere; update it the way you installed it)"}
	case m.MinFrom != "" && Newer(in.Current, m.MinFrom):
		return Decision{ActionNotify, fmt.Sprintf("%s is available (too big a jump from %s to install on its own)", m.Version, in.Current)}
	}
	return Decision{ActionInstall, "installing " + m.Version}
}

func clampPercent(p int) int {
	switch {
	case p < 0:
		return 0
	case p > 100:
		return 100
	}
	return p
}
