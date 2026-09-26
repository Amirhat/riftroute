package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Importing a profile lists every file it pulled in, and never reads one
// outside the profile's folder (here: a credentials file one level up).
func TestReadProfileListsFilesAndStaysInItsFolder(t *testing.T) {
	top := t.TempDir()
	dir := filepath.Join(top, "vpn")
	for name, body := range map[string]string{
		"vpn/ca.crt":      "CA\n",
		"secret.txt":      "user\npass\n",
		"vpn/office.ovpn": "client\nremote 192.0.2.1\nca ca.crt\n",
		"vpn/evil.ovpn":   "client\nremote 192.0.2.1\nauth-user-pass ../secret.txt\n",
	} {
		p := filepath.Join(top, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetErr(&stderr)

	text, creds, err := readProfile(cmd, filepath.Join(dir, "office.ovpn"))
	if err != nil || creds != nil || !strings.Contains(text, "<ca>\nCA\n</ca>") {
		t.Fatalf("got %q, %+v, %v", text, creds, err)
	}
	if want := "inlined 1 file(s) the profile refers to:\n  " + filepath.Join(dir, "ca.crt") + "\n"; stderr.String() != want {
		t.Errorf("stderr = %q, want %q", stderr.String(), want)
	}

	_, creds, err = readProfile(cmd, filepath.Join(dir, "evil.ovpn"))
	if err == nil || creds != nil || !strings.Contains(err.Error(), "outside the profile's folder") {
		t.Fatalf("evil profile: creds %+v, err %v", creds, err)
	}
}
