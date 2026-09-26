// Command riftroute-release is the maintainer's release-signing tool. It runs
// only on the maintainer's machine — the private key never goes to the server
// or to CI — and never takes a passphrase as an argument.
//
//	riftroute-release keygen                 new key → ~/.config/riftroute/release-key
//	riftroute-release pubkey                 print the public key and key ID
//	riftroute-release sign v0.2.6 [-min-from 0.2.4] [-channel stable]
//	                                          build + sign dist/release/v0.2.6/manifest.json
//	riftroute-release publish v0.2.6         upload manifest + signature to the GitHub release
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/Amirhat/riftroute/internal/update"
)

const repoAPI = "https://api.github.com/repos/Amirhat/riftroute"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen()
	case "pubkey":
		err = pubkey()
	case "sign":
		err = sign(os.Args[2:])
	case "publish":
		err = publish(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "riftroute-release:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: riftroute-release keygen | pubkey | sign <tag> [-min-from x.y.z] [-channel stable] | publish <tag>")
	os.Exit(2)
}

// keyPath is where the encrypted private key lives. RIFTROUTE_RELEASE_KEY
// overrides it (a path, never the key itself).
func keyPath() string {
	if p := os.Getenv("RIFTROUTE_RELEASE_KEY"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "riftroute", "release-key")
}

func keygen() error {
	path := keyPath()
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists — refusing to overwrite a release key", path)
	}
	pw, err := readPassphrase(true)
	if err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	blob, err := sealKey(priv, pw)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(blob); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "release key written to %s (0600, encrypted with your passphrase)\n", path)
	fmt.Fprintln(os.Stderr, "Back it up somewhere offline. Without it (or its passphrase) no new release can be signed.")
	printPub(pub)
	return nil
}

func pubkey() error {
	blob, err := os.ReadFile(keyPath())
	if err != nil {
		return err
	}
	var kf keyFile
	if err := json.Unmarshal(blob, &kf); err != nil {
		return err
	}
	pub, err := base64.StdEncoding.DecodeString(kf.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("key file has no valid public key")
	}
	// The clear-text public key must be the one its ID names (the ID is bound
	// to the sealed private key); `sign` proves the pair itself.
	if update.KeyID(ed25519.PublicKey(pub)) != kf.KeyID {
		return errors.New("key file's public key doesn't match its key ID — the file was changed")
	}
	printPub(ed25519.PublicKey(pub))
	return nil
}

func printPub(pub ed25519.PublicKey) {
	fmt.Printf("key id:     %s\npublic key: %s\n\nfor internal/update/keys.go:\n\t%q: mustKey(%q),\n",
		update.KeyID(pub), base64.StdEncoding.EncodeToString(pub), update.KeyID(pub), base64.StdEncoding.EncodeToString(pub))
}

// readPassphrase prompts on the terminal (twice when creating). Never an
// argument, never an environment variable.
func readPassphrase(confirm bool) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("the passphrase is read from a terminal only")
	}
	fmt.Fprint(os.Stderr, "Release key passphrase: ")
	a, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if !confirm {
		return a, nil
	}
	if len([]rune(string(a))) < 12 {
		return nil, errors.New("use a passphrase of at least 12 characters")
	}
	fmt.Fprint(os.Stderr, "Again: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if string(a) != string(b) {
		return nil, errors.New("the two passphrases don't match")
	}
	return a, nil
}

// ---------------------------------------------------------------- signing

var reTarball = regexp.MustCompile(`^riftroute_(\d+\.\d+\.\d+)_(darwin|linux)_(amd64|arm64)\.tar\.gz$`)

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	minFrom := fs.String("min-from", "", "installs older than this are only notified (x.y.z)")
	channel := fs.String("channel", "stable", "release channel")
	if len(args) < 1 {
		usage()
	}
	tag := args[0]
	_ = fs.Parse(args[1:])

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	hc := &http.Client{Timeout: 15 * time.Minute}
	m, err := buildManifest(ctx, hc, repoAPI, tag, *channel, *minFrom, os.Stderr)
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')

	priv, err := loadKey()
	if err != nil {
		return err
	}
	sig := update.Sign(priv, body)
	// Belt and braces: the signature must verify against the key we'll ship.
	if _, err := update.Verify(body, mustJSON(sig), map[string]ed25519.PublicKey{sig.KeyID: priv.Public().(ed25519.PublicKey)}); err != nil {
		return fmt.Errorf("self-check failed: %w", err)
	}
	if _, trusted := update.TrustedKeys[sig.KeyID]; !trusted {
		fmt.Fprintf(os.Stderr, "WARNING: %s is not in internal/update/keys.go yet — released builds won't trust this signature\n", sig.KeyID)
	}
	dir := filepath.Join("dist", "release", tag)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), body, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json.sig"), append(mustJSON(sig), '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "signed %s %s (%d assets) with %s → %s/manifest.json{,.sig}\n", m.Channel, m.Version, len(m.Assets), sig.KeyID, dir)
	return nil
}

// buildManifest reads the release's assets and checksums.txt, downloads every
// asset it lists and hashes it itself (the manifest vouches for what the
// maintainer actually saw, not just for GitHub's checksum file), and returns
// the validated manifest.
func buildManifest(ctx context.Context, hc *http.Client, api, tag, channel, minFrom string, log io.Writer) (update.Manifest, error) {
	var rel struct {
		TagName     string    `json:"tag_name"`
		HTMLURL     string    `json:"html_url"`
		Draft       bool      `json:"draft"`
		Prerelease  bool      `json:"prerelease"`
		PublishedAt time.Time `json:"published_at"`
		Assets      []ghAsset `json:"assets"`
	}
	if err := getJSON(ctx, hc, api+"/releases/tags/"+tag, &rel); err != nil {
		return update.Manifest{}, err
	}
	if rel.Draft || rel.Prerelease {
		return update.Manifest{}, fmt.Errorf("%s is a draft or pre-release", tag)
	}
	version := strings.TrimPrefix(rel.TagName, "v")
	if !update.IsRelease(version) {
		return update.Manifest{}, fmt.Errorf("%s is not a release version", rel.TagName)
	}
	var sums map[string]string
	for _, a := range rel.Assets {
		if a.Name == "checksums.txt" {
			b, err := get(ctx, hc, a.URL, 1<<20)
			if err != nil {
				return update.Manifest{}, fmt.Errorf("checksums.txt: %w", err)
			}
			sums = update.ParseChecksums(string(b))
		}
	}
	if sums == nil {
		return update.Manifest{}, errors.New("release has no checksums.txt")
	}
	m := update.Manifest{
		Schema: update.ManifestSchema, Channel: channel, Version: version,
		Published: rel.PublishedAt.UTC(), NotesURL: rel.HTMLURL, MinFrom: minFrom,
	}
	sort.Slice(rel.Assets, func(i, j int) bool { return rel.Assets[i].Name < rel.Assets[j].Name })
	for _, a := range rel.Assets {
		os_, arch, kind, ok := classify(a.Name, version)
		if !ok {
			continue
		}
		want, listed := sums[a.Name]
		if !listed {
			return update.Manifest{}, fmt.Errorf("%s is not in checksums.txt", a.Name)
		}
		fmt.Fprintf(log, "  hashing %s (%d MB)…\n", a.Name, a.Size>>20)
		b, err := get(ctx, hc, a.URL, update.MaxAssetSize)
		if err != nil {
			return update.Manifest{}, fmt.Errorf("%s: %w", a.Name, err)
		}
		sum := sha256.Sum256(b)
		got := hex.EncodeToString(sum[:])
		if !strings.EqualFold(got, want) || int64(len(b)) != a.Size {
			return update.Manifest{}, fmt.Errorf("%s: downloaded file doesn't match checksums.txt / the release listing", a.Name)
		}
		m.Assets = append(m.Assets, update.ManifestAsset{OS: os_, Arch: arch, Kind: kind, URL: a.URL, SHA256: got, Size: a.Size})
	}
	if _, ok := m.Asset("darwin", "arm64", "tarball"); !ok {
		return update.Manifest{}, errors.New("release has no darwin/arm64 tarball — refusing to sign an incomplete release")
	}
	return m, m.Validate()
}

// classify maps a release file name to (os, arch, kind); unknown names are
// left out of the manifest.
func classify(name, version string) (string, string, string, bool) {
	if mm := reTarball.FindStringSubmatch(name); mm != nil && mm[1] == version {
		return mm[2], mm[3], "tarball", true
	}
	switch {
	case name == "RiftRoute_"+version+".dmg":
		return "darwin", "universal", "app-dmg", true
	case name == "RiftRoute-"+version+"-x86_64.AppImage":
		return "linux", "amd64", "app-appimage", true
	case name == "riftroute_"+version+"_amd64.deb":
		return "linux", "amd64", "deb", true
	case name == "riftroute_"+version+"_arm64.deb":
		return "linux", "arm64", "deb", true
	}
	return "", "", "", false
}

func publish(args []string) error {
	if len(args) < 1 {
		usage()
	}
	tag := args[0]
	dir := filepath.Join("dist", "release", tag)
	files := []string{filepath.Join(dir, "manifest.json"), filepath.Join(dir, "manifest.json.sig")}
	body, err := os.ReadFile(files[0])
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(files[1])
	if err != nil {
		return err
	}
	// Only ever publish what a shipped build will accept.
	if _, err := update.Verify(body, sig, update.TrustedKeys); err != nil {
		return fmt.Errorf("refusing to publish: %w", err)
	}
	cmd := exec.Command("gh", append([]string{"release", "upload", tag, "--clobber"}, files...)...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gh release upload: %w", err)
	}
	fmt.Fprintf(os.Stderr, "published %s manifest to the GitHub release (the server copy is uploaded with scripts/publish-manifest.sh)\n", tag)
	return nil
}

func loadKey() (ed25519.PrivateKey, error) {
	blob, err := os.ReadFile(keyPath())
	if err != nil {
		return nil, fmt.Errorf("release key: %w (create one with: riftroute-release keygen)", err)
	}
	if fi, err := os.Stat(keyPath()); err == nil && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by others (mode %o) — chmod 600 it first", keyPath(), fi.Mode().Perm())
	}
	pw, err := readPassphrase(false)
	if err != nil {
		return nil, err
	}
	return openKey(blob, pw)
}

// ---------------------------------------------------------------- http

func getJSON(ctx context.Context, hc *http.Client, url string, v any) error {
	b, err := get(ctx, hc, url, 8<<20)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func get(ctx context.Context, hc *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "riftroute-release")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(bufio.NewReader(resp.Body), limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("GET %s: larger than %d bytes", url, limit)
	}
	return b, nil
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
