package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) (ed25519.PrivateKey, map[string]ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, map[string]ed25519.PublicKey{KeyID(pub): pub}
}

func goodManifest() Manifest {
	return Manifest{
		Schema: 1, Channel: "stable", Version: "0.2.6",
		Published: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
		Assets: []ManifestAsset{{
			OS: "darwin", Arch: "arm64", Kind: "tarball",
			URL:    "https://github.com/Amirhat/riftroute/releases/download/v0.2.6/riftroute_0.2.6_darwin_arm64.tar.gz",
			SHA256: strings.Repeat("ab", 32), Size: 15 << 20,
		}},
	}
}

func signed(t *testing.T, priv ed25519.PrivateKey, m Manifest) ([]byte, []byte) {
	t.Helper()
	body, _ := json.Marshal(m)
	sig, _ := json.Marshal(Sign(priv, body))
	return body, sig
}

func TestVerifyAcceptsOnlyTheExactSignedBytes(t *testing.T) {
	priv, keys := testKey(t)
	body, sig := signed(t, priv, goodManifest())
	m, err := Verify(body, sig, keys)
	if err != nil || m.Version != "0.2.6" {
		t.Fatalf("verify: %v %+v", err, m)
	}
	tampered := []byte(strings.Replace(string(body), "0.2.6", "9.9.9", 1))
	if _, err := Verify(tampered, sig, keys); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered manifest: %v", err)
	}
	// Another key's signature, or a key we don't trust.
	other, _ := testKey(t)
	_, sig2 := signed(t, other, goodManifest())
	if _, err := Verify(body, sig2, keys); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key: %v", err)
	}
	if _, err := Verify(body, sig, map[string]ed25519.PublicKey{}); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("no trusted keys: %v", err)
	}
	var s Signature
	_ = json.Unmarshal(sig, &s)
	s.Alg = "rsa"
	bad, _ := json.Marshal(s)
	if _, err := Verify(body, bad, keys); err == nil {
		t.Fatal("other algorithm accepted")
	}
}

// A validly signed manifest that asks for something unsafe is still refused.
func TestValidateRejectsUnsafeManifests(t *testing.T) {
	priv, keys := testKey(t)
	for name, mutate := range map[string]func(*Manifest){
		"http url":      func(m *Manifest) { m.Assets[0].URL = "http://github.com/x.tar.gz" },
		"other host":    func(m *Manifest) { m.Assets[0].URL = "https://evil.example/x.tar.gz" },
		"credentials":   func(m *Manifest) { m.Assets[0].URL = "https://u:p@github.com/x.tar.gz" },
		"odd port":      func(m *Manifest) { m.Assets[0].URL = "https://github.com:8443/x.tar.gz" },
		"bad hash":      func(m *Manifest) { m.Assets[0].SHA256 = "XYZ" },
		"huge":          func(m *Manifest) { m.Assets[0].Size = MaxAssetSize + 1 },
		"no size":       func(m *Manifest) { m.Assets[0].Size = 0 },
		"duplicate":     func(m *Manifest) { m.Assets = append(m.Assets, m.Assets[0]) },
		"no assets":     func(m *Manifest) { m.Assets = nil },
		"future schema": func(m *Manifest) { m.Schema = 2 },
		"dev version":   func(m *Manifest) { m.Version = "0.2.6-rc1" },
		"bad channel":   func(m *Manifest) { m.Channel = "Stable/../x" },
		"bad min_from":  func(m *Manifest) { m.MinFrom = "latest" },
	} {
		m := goodManifest()
		mutate(&m)
		body, sig := signed(t, priv, m)
		if _, err := Verify(body, sig, keys); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestIsReleaseAndAssetURLs(t *testing.T) {
	for v, want := range map[string]bool{"0.2.5": true, "v1.0.0": true, "0.2.4-8-gd4501c1": false, "0.2.5-dev": false, "1.2": false, "": false} {
		if IsRelease(v) != want {
			t.Errorf("IsRelease(%q) != %v", v, want)
		}
	}
	for u, want := range map[string]bool{
		"https://github.com/Amirhat/riftroute/releases/download/v1/x.tar.gz": true,
		"https://objects.githubusercontent.com/a/b":                          true,
		"https://GITHUB.COM/x":                                               true,
		"https://github.com.evil.example/x":                                  false,
		"http://github.com/x":                                                false,
		"file:///etc/passwd":                                                 false,
	} {
		if AllowedAssetURL(u) != want {
			t.Errorf("AllowedAssetURL(%q) != %v", u, want)
		}
	}
}

func TestDecide(t *testing.T) {
	base := DecideInput{Current: "0.2.5", Mode: "auto", Manifest: goodManifest(), Bucket: 40, GOOS: "darwin", GOARCH: "arm64", SelfUpdatable: true}
	cases := []struct {
		name string
		mod  func(*DecideInput)
		want Action
	}{
		{"installs a newer release", func(*DecideInput) {}, ActionInstall},
		{"off means nothing", func(in *DecideInput) { in.Mode = "off" }, ActionNone},
		{"same version", func(in *DecideInput) { in.Current = "0.2.6" }, ActionNone},
		{"never backwards", func(in *DecideInput) { in.Current = "0.3.0" }, ActionNone},
		{"notify mode", func(in *DecideInput) { in.Mode = "notify" }, ActionNotify},
		{"halt holds", func(in *DecideInput) { in.Advice = &Advice{RolloutPercent: 100, Halt: true} }, ActionHold},
		{"outside rollout holds", func(in *DecideInput) { in.Advice = &Advice{RolloutPercent: 25} }, ActionHold},
		{"inside rollout installs", func(in *DecideInput) { in.Advice = &Advice{RolloutPercent: 50} }, ActionInstall},
		{"0% holds everyone", func(in *DecideInput) { in.Bucket = 0; in.Advice = &Advice{RolloutPercent: 0} }, ActionHold},
		{"fallback (no advice) installs", func(in *DecideInput) { in.Advice = nil }, ActionInstall},
		{"rolled-back version skipped", func(in *DecideInput) { in.Skip = "0.2.6" }, ActionNone},
		{"newer than the skipped one offered", func(in *DecideInput) { in.Skip = "0.2.5" }, ActionInstall},
		{"dev build only notified", func(in *DecideInput) { in.Current = "0.2.4-8-gd4501c1" }, ActionNotify},
		{"package-managed only notified", func(in *DecideInput) { in.SelfUpdatable = false }, ActionNotify},
		{"no asset for this platform", func(in *DecideInput) { in.GOARCH = "riscv64" }, ActionNotify},
		{"too big a jump", func(in *DecideInput) { in.Manifest.MinFrom = "0.2.6"; in.Current = "0.2.5" }, ActionNotify},
		{"halt beats notify", func(in *DecideInput) { in.Mode = "notify"; in.Advice = &Advice{Halt: true} }, ActionHold},
	}
	for _, c := range cases {
		in := base
		in.Manifest = goodManifest()
		c.mod(&in)
		if got := Decide(in); got.Action != c.want {
			t.Errorf("%s: got %s (%s), want %s", c.name, got.Action, got.Reason, c.want)
		}
	}
}

// A mistyped entry in keys.go (wrong ID for its key) would silently make
// every release unverifiable; catch it at test time.
func TestTrustedKeysMatchTheirIDs(t *testing.T) {
	if len(TrustedKeys) == 0 || len(TrustedKeys) > 2 {
		t.Fatalf("want 1–2 trusted keys, have %d", len(TrustedKeys))
	}
	for id, pub := range TrustedKeys {
		if KeyID(pub) != id {
			t.Errorf("%s holds a key whose ID is %s", id, KeyID(pub))
		}
	}
}
