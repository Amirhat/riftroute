// Package update implements a safe, opt-in update CHECK against GitHub Releases
// (spec §14). It is deliberately conservative: it only *reports* whether a newer
// release exists and verifies a downloaded asset's SHA-256 against the release's
// published checksums. It never replaces a running binary on its own — applying
// an update is a documented, privileged, signed step. The agent never performs a
// self-update on a live host.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultAPI is the GitHub releases endpoint for the project repo.
const DefaultAPI = "https://api.github.com/repos/Amirhat/riftroute/releases/latest"

// Asset is a downloadable release artifact.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

// Release is the subset of the GitHub release payload we use.
type Release struct {
	TagName string  `json:"tag_name"`
	HTMLURL string  `json:"html_url"`
	Body    string  `json:"body"`
	Assets  []Asset `json:"assets"`
}

// Result is the outcome of an update check.
type Result struct {
	Current   string  `json:"current"`
	Latest    string  `json:"latest"`
	Available bool    `json:"available"`
	URL       string  `json:"url,omitempty"`
	Notes     string  `json:"notes,omitempty"`
	Assets    []Asset `json:"assets,omitempty"`
}

// Check queries the releases API and compares the latest tag with current.
// apiURL defaults to DefaultAPI; client defaults to a 10s-timeout client.
func Check(ctx context.Context, client *http.Client, apiURL, current string) (Result, error) {
	if apiURL == "" {
		apiURL = DefaultAPI
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("releases API: %s", resp.Status)
	}
	var rel Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return Result{}, fmt.Errorf("decode release: %w", err)
	}
	res := Result{
		Current:   current,
		Latest:    rel.TagName,
		URL:       rel.HTMLURL,
		Notes:     rel.Body,
		Assets:    rel.Assets,
		Available: Newer(current, rel.TagName),
	}
	return res, nil
}

// Newer reports whether candidate is a strictly newer semver than current.
// Non-semver or equal/older candidates return false (fail-closed).
func Newer(current, candidate string) bool {
	c, ok1 := parseSemver(current)
	n, ok2 := parseSemver(candidate)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < 3; i++ {
		if n[i] != c[i] {
			return n[i] > c[i]
		}
	}
	return false
}

func parseSemver(v string) ([3]int, bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i] // drop pre-release / build metadata
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// VerifySHA256 reports whether data matches the given hex digest (constant-form
// comparison after decode). Used to verify a downloaded asset against the
// release's published checksums before any apply step.
func VerifySHA256(data []byte, wantHex string) bool {
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	return strings.EqualFold(strings.TrimSpace(got), strings.TrimSpace(wantHex))
}

// ParseChecksums parses a `sha256sum`-style file (lines of "<hex>  <name>") into
// a name→digest map.
func ParseChecksums(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 {
			out[strings.TrimPrefix(f[len(f)-1], "*")] = f[0]
		}
	}
	return out
}
