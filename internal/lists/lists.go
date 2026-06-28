// Package lists handles reusable rule lists: static (inline) sets and remote
// subscribable sources (spec §5.1/§6/§12). Remote lists are HTTPS-only,
// size-limited, validated as CIDR/IP, and checksummed; list contents are NEVER
// executed — only parsed. GeoIP/ASN lookup lands later in M5.
package lists

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// MaxBytes caps a remote list download (defense against a hostile/huge source).
const MaxBytes = 8 << 20 // 8 MiB

// httpClient is the client used for fetches; tests override it to point at an
// httptest TLS server.
var httpClient = http.DefaultClient

// Fetch downloads a remote list over HTTPS, enforces the size limit, parses and
// validates entries as CIDR/IP, and returns the entries plus a sha256 checksum.
func Fetch(ctx context.Context, source string) (entries []string, checksum string, err error) {
	if !strings.HasPrefix(source, "https://") {
		return nil, "", fmt.Errorf("remote list source must be an https URL, got %q", source)
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetch list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("fetch list: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(body) > MaxBytes {
		return nil, "", fmt.Errorf("remote list exceeds %d bytes", MaxBytes)
	}
	sum := sha256.Sum256(body)
	return ParseEntries(body), hex.EncodeToString(sum[:]), nil
}

// ParseEntries extracts valid CIDR/IP entries from list bytes, one per line.
// Blank lines and '#'/';' comments (whole-line or inline) are ignored; invalid
// entries are skipped (never executed, only parsed — spec §12).
func ParseEntries(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// strip an inline comment / trailing tokens
		if i := strings.IndexAny(line, " \t#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if entry, ok := normalize(line); ok {
			out = append(out, entry)
		}
	}
	return out
}

func normalize(s string) (string, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().String(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String(), true
	}
	return "", false
}
