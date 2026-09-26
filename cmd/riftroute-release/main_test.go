package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/update"
)

func TestKeyFileRoundTripAndTamper(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	blob, err := sealKey(priv, []byte("correct horse battery"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "correct horse") {
		t.Fatal("passphrase leaked into the key file")
	}
	got, err := openKey(blob, []byte("correct horse battery"))
	if err != nil || !got.Equal(priv) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := openKey(blob, []byte("wrong horse battery")); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	var kf keyFile
	_ = json.Unmarshal(blob, &kf)
	kf.KeyID = "rr-0000000000000000" // swap the label: AAD must catch it
	swapped, _ := json.Marshal(kf)
	if _, err := openKey(swapped, []byte("correct horse battery")); err == nil {
		t.Fatal("changed key ID accepted")
	}
	_ = json.Unmarshal(blob, &kf)
	kf.N = 2 // a "cheap" file someone crafted
	weak, _ := json.Marshal(kf)
	if _, err := openKey(weak, []byte("correct horse battery")); err == nil {
		t.Fatal("weak scrypt parameters accepted")
	}
}

// rewrite sends every request (github.com, api.github.com, …) to the test
// server, keeping the path — so the manifest keeps the real URLs.
type rewrite struct{ target *url.URL }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host = r.target.Scheme, r.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

func fakeRelease(t *testing.T, tamper bool) *http.Client {
	files := map[string][]byte{
		"riftroute_0.2.6_darwin_arm64.tar.gz": []byte("darwin arm64 bits"),
		"riftroute_0.2.6_linux_amd64.tar.gz":  []byte("linux amd64 bits"),
		"RiftRoute_0.2.6.dmg":                 []byte("dmg bits"),
		"notes.txt":                           []byte("not a release file"),
	}
	var sums strings.Builder
	for name, b := range files {
		s := sha256.Sum256(b)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(s[:]), name)
	}
	if tamper {
		files["riftroute_0.2.6_linux_amd64.tar.gz"] = []byte("swapped after checksums were made")
	}
	files["checksums.txt"] = []byte(sums.String())
	var assets []map[string]any
	for name, b := range files {
		assets = append(assets, map[string]any{"name": name, "size": len(b),
			"browser_download_url": "https://github.com/Amirhat/riftroute/releases/download/v0.2.6/" + name})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/Amirhat/riftroute/releases/tags/v0.2.6", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": "v0.2.6", "html_url": "https://github.com/Amirhat/riftroute/releases/tag/v0.2.6",
			"published_at": "2026-10-01T12:00:00Z", "assets": assets})
	})
	mux.HandleFunc("/Amirhat/riftroute/releases/download/v0.2.6/", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		b, ok := files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return &http.Client{Transport: rewrite{u}}
}

func TestBuildManifestHashesEveryAsset(t *testing.T) {
	hc := fakeRelease(t, false)
	m, err := buildManifest(context.Background(), hc, "https://api.github.com/repos/Amirhat/riftroute", "v0.2.6", "stable", "0.2.4", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "0.2.6" || m.MinFrom != "0.2.4" || len(m.Assets) != 3 {
		t.Fatalf("manifest %+v", m)
	}
	if a, ok := m.Asset("darwin", "arm64", "tarball"); !ok || !strings.HasPrefix(a.URL, "https://github.com/") {
		t.Fatalf("darwin tarball %+v", a)
	}
	if _, ok := m.Asset("darwin", "universal", "app-dmg"); !ok {
		t.Fatal("dmg missing")
	}
	// Signing and verifying the built manifest works end to end.
	_, priv, _ := ed25519.GenerateKey(nil)
	body, _ := json.Marshal(m)
	sig, _ := json.Marshal(update.Sign(priv, body))
	if _, err := update.Verify(body, sig, map[string]ed25519.PublicKey{update.KeyID(priv.Public().(ed25519.PublicKey)): priv.Public().(ed25519.PublicKey)}); err != nil {
		t.Fatal(err)
	}
}

// A file that changed after checksums.txt was written must stop the signing.
func TestBuildManifestRefusesAMismatchedAsset(t *testing.T) {
	hc := fakeRelease(t, true)
	_, err := buildManifest(context.Background(), hc, "https://api.github.com/repos/Amirhat/riftroute", "v0.2.6", "stable", "", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "doesn't match") {
		t.Fatalf("want a mismatch error, got %v", err)
	}
}
