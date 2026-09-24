package tunnel

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

func TestParseVersion(t *testing.T) {
	for out, want := range map[string]string{
		"OpenVPN 2.7.7 aarch64-apple-darwin25.6.0 [SSL (OpenSSL)] [LZO]\nlibrary versions: OpenSSL 3.6.4": "2.7.7",
		"OpenVPN 2.4.7 x86_64-pc-linux-gnu [SSL (OpenSSL)]":                                               "2.4.7",
		"OpenVPN 2.6_git x86_64-pc-linux-gnu":                                                             "2.6_git",
		"OpenVPN 2.5 x86_64":                                                                              "2.5",
		"command not found":                                                                               "",
	} {
		if got := parseVersion([]byte(out)); got != want {
			t.Errorf("%q: got %q, want %q", out, got, want)
		}
	}
	for ver, old := range map[string]bool{"2.4.12": true, "2.3.18": true, "1.9": true, "2.5.0": false, "2.6_git": false, "3.0": false, "": false} {
		if tooOld(ver) != old {
			t.Errorf("tooOld(%q) = %v", ver, !old)
		}
	}
}

func TestParseOSRelease(t *testing.T) {
	got := parseOSRelease([]byte("# comment\nNAME=\"Rocky Linux\"\nID=rocky\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID='9.4'\n\nbogus\n"))
	if got["NAME"] != "Rocky Linux" || got["ID"] != "rocky" || got["ID_LIKE"] != "rhel centos fedora" || got["VERSION_ID"] != "9.4" {
		t.Fatalf("got %v", got)
	}
}

func linuxHost(release string) hostInfo {
	return hostInfo{goos: "linux", osRelease: parseOSRelease([]byte(release))}
}

func TestInstallHelpPerSystem(t *testing.T) {
	cases := []struct {
		name   string
		h      hostInfo
		system string
		cmds   string
		note   string
	}{
		{"macOS with Homebrew", hostInfo{goos: "darwin", brew: true}, "macOS", "brew install openvpn", "OpenVPN Connect app doesn't"},
		{"macOS without Homebrew", hostInfo{goos: "darwin"}, "macOS", "brew install openvpn", "install it from brew.sh"},
		{"Ubuntu", linuxHost("PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\nID_LIKE=debian\n"), "Ubuntu 24.04.1 LTS", "sudo apt install openvpn", ""},
		{"Debian", linuxHost("PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\n"), "Debian GNU/Linux 12 (bookworm)", "sudo apt install openvpn", ""},
		{"Mint via ID_LIKE", linuxHost("NAME=\"Linux Mint\"\nID=linuxmint\nID_LIKE=\"ubuntu debian\"\n"), "Linux Mint", "sudo apt install openvpn", ""},
		{"Fedora", linuxHost("ID=fedora\n"), "Linux", "sudo dnf install openvpn", ""},
		{"Rocky before its fedora ID_LIKE", linuxHost("ID=rocky\nID_LIKE=\"rhel centos fedora\"\n"), "Linux", "sudo dnf install epel-release && sudo dnf install openvpn", "EPEL"},
		{"RHEL", linuxHost("ID=rhel\nID_LIKE=fedora\n"), "Linux", "sudo dnf install openvpn", "enable EPEL"},
		{"Manjaro via arch", linuxHost("ID=manjaro\nID_LIKE=arch\n"), "Linux", "sudo pacman -S openvpn", ""},
		{"openSUSE", linuxHost("ID=opensuse-tumbleweed\nID_LIKE=\"opensuse suse\"\n"), "Linux", "sudo zypper install openvpn", ""},
		{"Alpine", linuxHost("ID=alpine\n"), "Linux", "sudo apk add openvpn", ""},
		{"Oracle Linux: not its fedora ID_LIKE", linuxHost("ID=ol\nID_LIKE=fedora\n"), "Linux", "", "package manager"},
		{"Amazon Linux 2", linuxHost("ID=amzn\nID_LIKE=\"centos rhel fedora\"\n"), "Linux", "", "package manager"},
		{"unknown distro", linuxHost("ID=someos\n"), "Linux", "", "package manager"},
		{"no os-release", hostInfo{goos: "linux"}, "Linux", "", "package manager"},
	}
	for _, c := range cases {
		in := installHelp(c.h)
		if in.System != c.system || strings.Join(in.Commands, " && ") != c.cmds || !strings.Contains(in.Note, c.note) {
			t.Errorf("%s: got %+v", c.name, in)
		}
	}
}

type fakeFile struct{ os.FileInfo }

func TestDetectEngine(t *testing.T) {
	found := func(path string, err error) func() (string, os.FileInfo, error) {
		return func() (string, os.FileInfo, error) { return path, fakeFile{}, err }
	}
	ver := func(v string) func(string, os.FileInfo) (string, error) {
		return func(string, os.FileInfo) (string, error) { return v, nil }
	}
	cellar := "/opt/homebrew/Cellar/openvpn/2.7.7/sbin/openvpn"
	mac := hostInfo{goos: "darwin", brew: true}

	if e := detectEngine(mac, found("", errNotFound), nil); e.Available || e.Problem != "OpenVPN isn't installed" ||
		e.Install == nil || e.Install.Commands[0] != "brew install openvpn" {
		t.Errorf("missing: %+v", e)
	}
	unsafe := errors.New("/usr/sbin/openvpn is writable by other users, so RiftRoute won't run it as root")
	// Writable by others: it may have been changed, so reinstall, don't chmod.
	if e := detectEngine(linuxHost("ID=debian\n"), found("/usr/sbin/openvpn", unsafe), nil); e.Available ||
		!strings.Contains(e.Problem, "writable") || e.Install.Commands[0] != "sudo apt install --reinstall openvpn" ||
		!strings.Contains(e.Install.Note, "reinstall it") {
		t.Errorf("unsafe: %+v %+v", e, e.Install)
	}
	if e := detectEngine(mac, found(cellar, unsafe), nil); e.Install.Commands[0] != "brew reinstall openvpn" {
		t.Errorf("unsafe on macOS: %+v", e.Install)
	}
	if e := detectEngine(linuxHost("ID=someos\n"), found("/usr/sbin/openvpn", unsafe), nil); len(e.Install.Commands) != 0 ||
		!strings.Contains(e.Install.Note, "Reinstall openvpn (/usr/sbin/openvpn)") {
		t.Errorf("unsafe, unknown distro: %+v", e.Install)
	}
	// Installed but broken (e.g. a library it needs was removed).
	broken := func(string, os.FileInfo) (string, error) {
		return "", errors.New(cellar + " doesn't run: dyld: Library not loaded")
	}
	if e := detectEngine(mac, found(cellar, nil), broken); e.Available || !strings.Contains(e.Problem, "doesn't run") ||
		e.Install.Commands[0] != "brew reinstall openvpn" {
		t.Errorf("broken: %+v", e)
	}
	if e := detectEngine(linuxHost("ID=ubuntu\n"), found("/usr/sbin/openvpn", nil), ver("2.4.7")); e.Available ||
		!strings.Contains(e.Problem, "2.4.7 is too old") || e.Install.URL == "" || e.Version != "2.4.7" {
		t.Errorf("too old: %+v", e)
	}
	if e := detectEngine(mac, found(cellar, nil), ver("2.4.9")); e.Install.Commands[0] != "brew upgrade openvpn" {
		t.Errorf("too old on macOS: %+v", e.Install)
	}
	// An old MacPorts/hand-built openvpn isn't Homebrew's to upgrade; a
	// Homebrew one is found first once installed.
	if e := detectEngine(mac, found("/opt/local/sbin/openvpn", nil), ver("2.4.9")); e.Install.Commands[0] != "brew install openvpn" ||
		!strings.Contains(e.Install.Note, "ahead of /opt/local/sbin/openvpn") {
		t.Errorf("too old, not Homebrew: %+v", e.Install)
	}
	if e := detectEngine(mac, found("/opt/homebrew/sbin/openvpn", nil), ver("2.7.7")); !e.Available || e.Problem != "" ||
		e.Install != nil || e.Path != "/opt/homebrew/sbin/openvpn" || e.Version != "2.7.7" {
		t.Errorf("ok: %+v", e)
	}
	if e := detectEngine(mac, found("/opt/homebrew/sbin/openvpn", nil), ver("")); !e.Available {
		t.Errorf("an unreadable version must not block: %+v", e)
	}
	if e := detectEngine(hostInfo{goos: "windows"}, found("", errNotFound), nil); e.Available || !strings.Contains(e.Problem, "windows") {
		t.Errorf("unsupported OS: %+v", e)
	}
}

func TestEngineErrorCarriesTheInstallSteps(t *testing.T) {
	err := error(&EngineError{Engine: domain.TunnelEngine{Problem: "OpenVPN isn't installed", Install: &domain.TunnelInstall{
		System: "Ubuntu", Commands: []string{"sudo apt install openvpn"},
	}}})
	if !errors.Is(err, ErrEngineUnavailable) || err.Error() != "OpenVPN isn't installed — run `sudo apt install openvpn`." {
		t.Fatalf("got %q", err)
	}
}

// The real binary's version is read once per file identity, not per call.
func TestVersionCacheRunsOpenVPNOncePerBinary(t *testing.T) {
	bin := t.TempDir() + "/openvpn"
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho x >> \"$0.calls\"\necho 'OpenVPN 2.6.14 x86_64-pc-linux-gnu'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var c versionCache
	fi, _ := os.Stat(bin)
	for range 3 {
		if v, err := c.version(bin, fi); v != "2.6.14" || err != nil {
			t.Fatalf("version = %q, %v (exit status 1 must not hide it)", v, err)
		}
	}
	calls, _ := os.ReadFile(bin + ".calls")
	if n := strings.Count(string(calls), "x"); n != 1 {
		t.Fatalf("ran openvpn %d times", n)
	}
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(bin, later, later); err != nil {
		t.Fatal(err)
	}
	fi, _ = os.Stat(bin)
	_, _ = c.version(bin, fi)
	if calls, _ = os.ReadFile(bin + ".calls"); strings.Count(string(calls), "x") != 2 {
		t.Fatal("an upgraded binary must be probed again")
	}
}

// A binary that runs and fails is broken — and not remembered as such, so
// fixing it is noticed on the next look.
func TestVersionProbeReportsABrokenBinaryWithoutCachingIt(t *testing.T) {
	bin := t.TempDir() + "/openvpn"
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho x >> \"$0.calls\"\necho 'dyld: Library not loaded: libssl.3.dylib' >&2\nexit 134\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var c versionCache
	fi, _ := os.Stat(bin)
	for range 2 {
		if v, err := c.version(bin, fi); v != "" || err == nil || !strings.Contains(err.Error(), "doesn't run: dyld: Library not loaded") {
			t.Fatalf("got %q, %v", v, err)
		}
	}
	if calls, _ := os.ReadFile(bin + ".calls"); strings.Count(string(calls), "x") != 2 {
		t.Fatal("a failed probe must not be cached")
	}
}

func TestInstallSummaryReadsAsASentence(t *testing.T) {
	in := &domain.TunnelInstall{Commands: []string{"brew install openvpn"}, Note: connectNote}
	if got := in.Summary(); got != "run `brew install openvpn`. "+connectNote {
		t.Fatalf("got %q", got)
	}
	in = &domain.TunnelInstall{Note: "Enable EPEL first.", URL: "https://example.org"}
	if got := in.Summary(); got != "Enable EPEL first. https://example.org" {
		t.Fatalf("got %q", got)
	}
}
