package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/update"
)

func releaseKey(t *testing.T) (ed25519.PrivateKey, map[string]ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	return priv, map[string]ed25519.PublicKey{update.KeyID(pub): pub}
}

func signedRelease(t *testing.T, priv ed25519.PrivateKey, channel, version string) ([]byte, []byte) {
	t.Helper()
	m := update.Manifest{Schema: 1, Channel: channel, Version: version, Published: time.Unix(0, 0).UTC(),
		Assets: []update.ManifestAsset{{OS: "darwin", Arch: "arm64", Kind: "tarball",
			URL:    "https://github.com/Amirhat/riftroute/releases/download/v" + version + "/riftroute_" + version + "_darwin_arm64.tar.gz",
			SHA256: strings.Repeat("cd", 32), Size: 1 << 20}}}
	raw, _ := json.Marshal(m)
	sig, _ := json.Marshal(update.Sign(priv, raw))
	return raw, sig
}

func TestPublishedManifestIsServedByteForByte(t *testing.T) {
	priv, keys := releaseKey(t)
	e := newEnvKeys(t, "", keys)
	raw, sig := signedRelease(t, priv, "stable", "0.2.6")
	if _, err := PublishManifest(e.dir, "stable", raw, sig, 25, keys, e.now); err != nil {
		t.Fatal(err)
	}
	w := e.do("GET", "/api/v1/update/stable", nil)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "max-age=60") {
		t.Fatalf("update: %d %q", w.Code, w.Header().Get("Cache-Control"))
	}
	var r updateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	gotRaw, _ := base64.StdEncoding.DecodeString(r.Manifest)
	gotSig, _ := base64.StdEncoding.DecodeString(r.Signature)
	m, err := update.Verify(gotRaw, gotSig, keys) // what a client does
	if err != nil || m.Version != "0.2.6" || r.Advice.RolloutPercent != 25 || r.Advice.Halt {
		t.Fatalf("client view: %v %+v %+v", err, m, r.Advice)
	}
	for _, p := range []string{"/api/v1/update/beta", "/api/v1/update/..%2Fsecrets", "/api/v1/update/Stable"} {
		if w := e.do("GET", p, nil); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
}

func TestPublishRefusesWhatAClientWouldRefuse(t *testing.T) {
	priv, keys := releaseKey(t)
	other, _ := releaseKey(t)
	dir := t.TempDir()
	now := time.Unix(1_800_000_000, 0)
	raw, sig := signedRelease(t, priv, "stable", "0.2.6")
	if _, err := PublishManifest(dir, "stable", raw, sig, 100, keys, now); err != nil {
		t.Fatal(err)
	}
	oRaw, oSig := signedRelease(t, other, "stable", "0.2.7")
	if _, err := PublishManifest(dir, "stable", oRaw, oSig, 100, keys, now); err == nil {
		t.Error("unknown key accepted")
	}
	if _, err := PublishManifest(dir, "beta", raw, sig, 100, keys, now); err == nil {
		t.Error("manifest published to another channel")
	}
	oldRaw, oldSig := signedRelease(t, priv, "stable", "0.2.5")
	if _, err := PublishManifest(dir, "stable", oldRaw, oldSig, 100, keys, now); err == nil || !strings.Contains(err.Error(), "older") {
		t.Errorf("older version: %v", err)
	}
	if _, err := PublishManifest(dir, "stable", raw, sig, 100, keys, now); err != nil {
		t.Errorf("re-publishing the same version: %v", err)
	}
	if _, err := PublishManifest(dir, "stable", raw, append([]byte(" "), sig...), 101, keys, now); err == nil {
		t.Error("rollout 101 accepted")
	}
}

// A manifest changed on the server's disk (by anyone) is refused, not served.
func TestTamperedManifestOnDiskIsNotServed(t *testing.T) {
	priv, keys := releaseKey(t)
	e := newEnvKeys(t, "", keys)
	raw, sig := signedRelease(t, priv, "stable", "0.2.6")
	if _, err := PublishManifest(e.dir, "stable", raw, sig, 100, keys, e.now); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(e.dir, "updates", "stable", "manifest.json")
	if err := os.WriteFile(p, []byte(strings.Replace(string(raw), "0.2.6", "0.9.0", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if w := e.do("GET", "/api/v1/update/stable", nil); w.Code != http.StatusNotFound {
		t.Fatalf("tampered manifest served: %d", w.Code)
	}
	if !strings.Contains(e.logs.String(), "update channel unreadable") {
		t.Fatalf("tampering not logged:\n%s", e.logs.String())
	}
}

func TestAdminRolloutAndHalt(t *testing.T) {
	priv, keys := releaseKey(t)
	e := newEnvKeys(t, "correct horse battery", keys)
	raw, sig := signedRelease(t, priv, "stable", "0.2.6")
	if _, err := PublishManifest(e.dir, "stable", raw, sig, 5, keys, e.now); err != nil {
		t.Fatal(err)
	}
	sess := cookie(e.login("correct horse battery"), sessionCookie)
	page := e.do("GET", "/admin", nil, sess).Body.String()
	if !strings.Contains(page, "0.2.6") || !strings.Contains(page, "Halt rollout") {
		t.Fatalf("admin page lacks the release:\n%s", page)
	}
	csrf := reCSRF.FindStringSubmatch(page)[1]
	advice := func() update.Advice {
		var r updateResponse
		_ = json.Unmarshal(e.do("GET", "/api/v1/update/stable", nil).Body.Bytes(), &r)
		return r.Advice
	}
	post := func(v url.Values) int {
		v.Set("csrf", csrf)
		v.Set("channel", "stable")
		return e.do("POST", "/admin/releases", v, sess).Code
	}

	if c := post(url.Values{"action": {"rollout"}, "percent": {"50"}}); c != http.StatusSeeOther || advice().RolloutPercent != 50 {
		t.Fatalf("rollout 50: %d %+v", c, advice())
	}
	if c := post(url.Values{"action": {"halt"}}); c != http.StatusSeeOther || !advice().Halt {
		t.Fatalf("halt: %d %+v", c, advice())
	}
	if c := post(url.Values{"action": {"rollout"}, "percent": {"150"}}); c != http.StatusBadRequest {
		t.Fatalf("percent 150: %d", c)
	}
	// Without the session's CSRF token nothing changes.
	forged := url.Values{"csrf": {"forged"}, "channel": {"stable"}, "action": {"resume"}}
	if w := e.do("POST", "/admin/releases", forged, sess); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" || !advice().Halt {
		t.Fatalf("forged resume: %d %+v", w.Code, advice())
	}
	if c := post(url.Values{"action": {"resume"}}); c != http.StatusSeeOther || advice().Halt {
		t.Fatalf("resume: %d %+v", c, advice())
	}
	if !strings.Contains(e.logs.String(), "update rollout changed") {
		t.Fatal("rollout changes not logged")
	}
}
