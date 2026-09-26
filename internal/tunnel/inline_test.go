package tunnel

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// write creates dir/name (and its parent folders) holding body.
func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func TestInlineFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "ca.crt", "CA-PEM\n")
	write(t, dir, "ta.key", "TA-KEY\n")
	write(t, dir, "creds.txt", "bob\nhunter2\n")
	src := "client\nremote 192.0.2.1\nca ca.crt\ntls-auth ta.key 1\nauth-user-pass creds.txt\n<cert>\nINLINE\n</cert>\nextra-certs ca.crt\n"
	res, err := InlineFiles(src, dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.Creds == nil || res.Creds.Username != "bob" || res.Creds.Password != "hunter2" {
		t.Fatalf("creds = %+v", res.Creds)
	}
	// Every file read is reported once, in profile order, so the user sees it.
	want := []string{filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ta.key"), filepath.Join(dir, "creds.txt")}
	if !slices.Equal(res.Files, want) {
		t.Errorf("files = %q, want %q", res.Files, want)
	}
	p, err := Parse(res.Config)
	if err != nil {
		t.Fatalf("inlined profile does not parse: %v\n%s", err, res.Config)
	}
	r := p.Render(RenderOptions{Management: "/m"})
	for _, must := range []string{"<ca>\nCA-PEM\n</ca>", "key-direction 1", "<tls-auth>\nTA-KEY\n</tls-auth>", "<cert>\nINLINE\n</cert>", "auth-user-pass\n"} {
		if !strings.Contains(r, must) {
			t.Errorf("missing %q in\n%s", must, r)
		}
	}
	if strings.Contains(r, "hunter2") || strings.Contains(r, "creds.txt") {
		t.Error("credentials file leaked into the config")
	}
}

func TestInlineFilesWithoutReferencesReadsNothing(t *testing.T) {
	res, err := InlineFiles("client\nremote 192.0.2.1\nauth-user-pass\nca [inline]\n<ca>\nX\n</ca>\n", filepath.Join(t.TempDir(), "gone"))
	if err != nil || len(res.Files) != 0 || res.Creds != nil {
		t.Fatalf("got %+v, %v", res, err)
	}
}

// A downloaded profile must not make the importer read the user's other
// files: `auth-user-pass ~/.aws/credentials` would send its first two lines
// to the profile's server, and a key directive would copy e.g. an SSH key
// into the tunnel store.
func TestInlineFilesStaysInTheProfilesFolder(t *testing.T) {
	top := t.TempDir()
	secret := write(t, top, "secret.txt", "SECRET-USER\nSECRET-PASS\n")
	dir := filepath.Join(top, "vpn")
	write(t, dir, "ca.crt", "CA\n")
	symlink(t, "../secret.txt", filepath.Join(dir, "rel-link.crt"))
	symlink(t, secret, filepath.Join(dir, "abs-link.crt"))
	symlink(t, top, filepath.Join(dir, "up"))

	for _, line := range []string{
		"auth-user-pass ../secret.txt",
		"auth-user-pass " + secret,
		"ca ../secret.txt",
		"key " + secret,
		"cert sub/../../secret.txt",
		"ca rel-link.crt",
		"ca abs-link.crt",
		"tls-auth up/secret.txt 1",
		"auth-user-pass up/secret.txt",
		"pkcs12 ../vpn/../secret.txt",
		"ca /etc/hosts",
	} {
		res, err := InlineFiles("client\nremote 192.0.2.1\n"+line+"\n", dir)
		if err == nil || !strings.Contains(err.Error(), "outside the profile's folder") {
			t.Errorf("%q: got %v, want it refused as outside the folder", line, err)
		}
		if res != nil && strings.Contains(res.Config, "SECRET") {
			t.Errorf("%q: read the secret", line)
		}
	}
}

func TestInlineFilesAllowsFilesUnderTheFolder(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "certs/ca.crt", "CA\n")
	symlink(t, "certs/ca.crt", filepath.Join(dir, "link.crt"))
	real, err := filepath.EvalSymlinks(dir) // macOS: /var → /private/var
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{
		"certs/ca.crt", "./certs/ca.crt", "certs/../certs/ca.crt", "link.crt",
		filepath.Join(dir, "certs/ca.crt"), filepath.Join(real, "certs/ca.crt"),
	} {
		res, err := InlineFiles("client\nremote 192.0.2.1\nca "+quote(ref)+"\n", dir)
		if err != nil {
			t.Errorf("%s: %v", ref, err)
			continue
		}
		if !strings.Contains(res.Config, "<ca>\nCA\n</ca>") || len(res.Files) != 1 {
			t.Errorf("%s: got %+v", ref, res)
		}
	}
}

func TestInlineFilesReadsOnlySmallRegularFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "certs"), 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, dir, "big.crt", strings.Repeat("A", maxRefFileBytes+1))
	chunk := strings.Repeat("B", 200<<10)
	for _, n := range []string{"a.crt", "b.crt", "c.crt"} {
		write(t, dir, n, chunk)
	}
	for line, want := range map[string]string{
		"ca certs":                               "not a regular file",
		"ca big.crt":                             "larger than 256 KiB",
		"ca a.crt\ncert b.crt\nextra-certs c.crt": "larger than 512 KiB",
		"ca missing.crt":                         "missing.crt",
	} {
		_, err := InlineFiles("client\nremote 192.0.2.1\n"+line+"\n", dir)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want an error containing %q", line, err, want)
		}
	}
}

// Credentials are the riskiest file a profile can name: beyond staying in the
// profile's folder, they may not come from a dotfile or a dot-folder.
func TestInlineFilesRefusesHiddenCredentialFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".config", "vpn") // the profile itself may live in one
	write(t, dir, "creds.txt", "bob\npw\n")
	write(t, dir, ".creds", "bob\npw\n")
	write(t, dir, ".secret/creds", "bob\npw\n")
	write(t, dir, ".certs/ca.crt", "CA\n")
	symlink(t, ".secret/creds", filepath.Join(dir, "plain-link"))
	symlink(t, "creds.txt", filepath.Join(dir, ".dot-link"))

	for _, ref := range []string{".creds", ".secret/creds", "plain-link", ".dot-link", filepath.Join(dir, ".creds")} {
		_, err := InlineFiles("client\nremote 192.0.2.1\nauth-user-pass "+ref+"\n", dir)
		if err == nil || !strings.Contains(err.Error(), "hidden") {
			t.Errorf("%s: got %v, want it refused as hidden", ref, err)
		}
	}
	res, err := InlineFiles("client\nremote 192.0.2.1\nauth-user-pass creds.txt\nca .certs/ca.crt\n", dir)
	if err != nil || res.Creds == nil || res.Creds.Username != "bob" {
		t.Fatalf("plain credentials next to the profile: %+v, %v", res, err)
	}
}

func TestReadProfileFile(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "office.ovpn", "client\nremote 192.0.2.1\n")
	if text, err := ReadProfileFile(p); err != nil || text != "client\nremote 192.0.2.1\n" {
		t.Fatalf("got %q, %v", text, err)
	}
	if _, err := ReadProfileFile(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("directory: %v", err)
	}
	big := write(t, dir, "big.ovpn", strings.Repeat("#\n", maxProfileBytes/2+1))
	if _, err := ReadProfileFile(big); err == nil || !strings.Contains(err.Error(), "larger than 512 KiB") {
		t.Errorf("big profile: %v", err)
	}
}
