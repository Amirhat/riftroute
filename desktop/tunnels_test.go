package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

func writeFiles(t *testing.T, top string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(top, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// The editor gets the files the import read (as "files"), and a profile
// pointing outside its folder gets an error — never the file's content as a
// username and password.
func TestLoadTunnelProfile(t *testing.T) {
	top := t.TempDir()
	writeFiles(t, top, map[string]string{
		"vpn/ca.crt":      "CA\n",
		"vpn/login.txt":   "alice\ns3cret\n",
		"git-credentials": "https://bob:token@example.com\n",
		"vpn/office.ovpn": "client\nremote 192.0.2.1\nca ca.crt\nauth-user-pass login.txt\n",
		"vpn/evil.ovpn":   "client\nremote 192.0.2.1\nauth-user-pass ../git-credentials\n",
	})
	dir := filepath.Join(top, "vpn")

	f, err := loadTunnelProfile(filepath.Join(dir, "office.ovpn"))
	if err != nil || f.Error != "" {
		t.Fatalf("office: %v %q", err, f.Error)
	}
	if want := []string{filepath.Join(dir, "ca.crt"), filepath.Join(dir, "login.txt")}; !slices.Equal(f.Files, want) {
		t.Errorf("files = %q, want %q", f.Files, want)
	}
	if f.Username != "alice" || f.Password != "s3cret" || !f.NeedsAuth {
		t.Errorf("login = %q/%q needs=%v", f.Username, f.Password, f.NeedsAuth)
	}
	js, err := json.Marshal(f)
	if err != nil || !strings.Contains(string(js), `"files":[`) {
		t.Errorf("json = %s (%v)", js, err)
	}

	f, err = loadTunnelProfile(filepath.Join(dir, "evil.ovpn"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.Error, "outside the profile's folder") || f.Username != "" || f.Password != "" {
		t.Errorf("evil profile: error %q, login %q/%q", f.Error, f.Username, f.Password)
	}
	if js, _ := json.Marshal(f); !strings.Contains(string(js), `"files":[]`) {
		t.Errorf("files must be an empty list, not null: %s", js)
	}

	if _, err := loadTunnelProfile(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a folder picked as the profile: %v", err)
	}
}

// A wg-quick file loads as WireGuard: as it is (nothing to inline, no
// login), with its endpoints and what's ignored for the editor.
func TestLoadTunnelProfileWireGuard(t *testing.T) {
	dir := t.TempDir()
	key := func(b byte) string { return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(rune(b)), 32))) }
	text := "[Interface]\nPrivateKey = " + key('a') + "\nAddress = 10.64.0.2/32\nDNS = 10.64.0.1\nPostUp = echo hi\n" +
		"[Peer]\nPublicKey = " + key('b') + "\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"
	writeFiles(t, dir, map[string]string{"lab.conf": text, "bad.conf": "[Interface]\nAddress = 10.64.0.2/32\n"})

	f, err := loadTunnelProfile(filepath.Join(dir, "lab.conf"))
	if err != nil || f.Error != "" {
		t.Fatalf("lab: %v %q", err, f.Error)
	}
	if f.Type != domain.TunnelWireGuard || f.Config != text || f.NeedsAuth || len(f.Files) != 0 {
		t.Errorf("lab = %+v", f)
	}
	if !slices.Equal(f.Servers, []string{"vpn.example.com:51820/udp"}) || !slices.Equal(f.Ignored, []string{"DNS", "PostUp"}) {
		t.Errorf("servers %q ignored %q", f.Servers, f.Ignored)
	}

	f, err = loadTunnelProfile(filepath.Join(dir, "bad.conf"))
	if err != nil || f.Type != domain.TunnelWireGuard || !strings.Contains(f.Error, "PrivateKey") {
		t.Errorf("bad: %v %+v", err, f)
	}
}
