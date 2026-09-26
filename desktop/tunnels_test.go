package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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
