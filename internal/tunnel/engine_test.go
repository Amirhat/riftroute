package tunnel

import (
	"errors"
	"os"
	"runtime"
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

var mac = hostInfo{goos: "darwin"}

func TestInstallHelpPerSystem(t *testing.T) {
	cases := []struct {
		name   string
		h      hostInfo
		system string
		cmds   string
		note   string
	}{
		{"macOS: the openvpn that ships with RiftRoute", mac, "macOS", "", "ships with RiftRoute — reinstall the daemon"},
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
	shipped := "/Library/PrivilegedHelperTools/riftroute-openvpn"
	var seen []domain.TunnelEngine
	check := func(e domain.TunnelEngine) domain.TunnelEngine { seen = append(seen, e); return e }

	// macOS: whatever is wrong, the fix is RiftRoute's own openvpn — never Homebrew.
	if e := check(detectEngine(mac, found("", errNotFound), nil)); e.Available || e.Problem != "OpenVPN isn't installed" ||
		e.Install == nil || len(e.Install.Commands) != 0 || e.Install.Note != macReinstall || e.Install.URL != releasesURL {
		t.Errorf("missing on macOS: %+v %+v", e, e.Install)
	}
	notRoots := &unsafeError{Bin: shipped, Path: shipped, Why: "isn't owned by root"}
	if e := check(detectEngine(mac, found(shipped, notRoots), nil)); e.Available || !strings.Contains(e.Problem, "isn't owned by root") ||
		!strings.Contains(e.Install.Note, "reinstall it rather than") || !strings.Contains(e.Install.Note, macReinstall) {
		t.Errorf("unsafe on macOS: %+v %+v", e, e.Install)
	}
	broken := func(string, os.FileInfo) (string, error) {
		return "", errors.New(shipped + " doesn't run: dyld: Library not loaded")
	}
	if e := check(detectEngine(mac, found(shipped, nil), broken)); e.Available || !strings.Contains(e.Problem, "doesn't run") ||
		e.Install.Note != macReinstall {
		t.Errorf("broken on macOS: %+v %+v", e, e.Install)
	}
	if e := check(detectEngine(mac, found(shipped, nil), ver("2.4.9"))); e.Available || e.Install.Note != macReinstall {
		t.Errorf("too old on macOS: %+v", e.Install)
	}
	if e := check(detectEngine(mac, found(shipped, nil), ver("2.6.23"))); !e.Available || e.Problem != "" ||
		e.Install != nil || e.Path != shipped || e.Version != "2.6.23" {
		t.Errorf("ok: %+v", e)
	}
	if e := check(detectEngine(mac, found(shipped, nil), ver(""))); !e.Available {
		t.Errorf("a version openvpn ran without printing must not block: %+v", e)
	}
	// A probe that couldn't run it at all (as nobody) is not "available".
	unchecked := func(string, os.FileInfo) (string, error) {
		return "", errors.New(shipped + " couldn't be checked: fork/exec: permission denied")
	}
	if e := check(detectEngine(mac, found(shipped, nil), unchecked)); e.Available || !strings.Contains(e.Problem, "couldn't be checked") {
		t.Errorf("unprobed: %+v", e)
	}

	// Linux: the distribution's package.
	bin := "/usr/sbin/openvpn"
	writable := &unsafeError{Bin: bin, Path: bin, Why: "is writable by other users"}
	// Writable by others: it may have been changed, so reinstall, don't chmod.
	if e := check(detectEngine(linuxHost("ID=debian\n"), found(bin, writable), nil)); e.Available ||
		!strings.Contains(e.Problem, "writable") || e.Install.Commands[0] != "sudo apt install --reinstall openvpn" ||
		!strings.Contains(e.Install.Note, "reinstall it") {
		t.Errorf("unsafe: %+v %+v", e, e.Install)
	}
	notRoot := &unsafeError{Bin: bin, Path: bin, Why: "isn't owned by root"}
	if e := check(detectEngine(linuxHost("ID=fedora\n"), found(bin, notRoot), nil)); e.Available ||
		e.Problem != "/usr/sbin/openvpn isn't owned by root, so RiftRoute won't run it as root" ||
		e.Install.Commands[0] != "sudo dnf reinstall openvpn" || !strings.Contains(e.Install.Note, "must belong to root") {
		t.Errorf("not root's: %+v %+v", e, e.Install)
	}
	dir := &unsafeError{Bin: bin, Path: "/usr/sbin", Why: "is writable by other users"}
	if e := check(detectEngine(linuxHost("ID=ubuntu\n"), found(bin, dir), nil)); e.Available ||
		e.Problem != "the folder /usr/sbin is writable by other users, so RiftRoute won't run /usr/sbin/openvpn as root" ||
		!strings.Contains(e.Install.Note, "Make /usr/sbin owned by root") || e.Install.Commands[0] != "sudo apt install --reinstall openvpn" {
		t.Errorf("unsafe folder: %+v %+v", e, e.Install)
	}
	if e := check(detectEngine(linuxHost("ID=someos\n"), found(bin, writable), nil)); len(e.Install.Commands) != 0 ||
		!strings.Contains(e.Install.Note, "Reinstall openvpn (/usr/sbin/openvpn)") {
		t.Errorf("unsafe, unknown distro: %+v", e.Install)
	}
	if e := check(detectEngine(linuxHost("ID=ubuntu\n"), found(bin, nil), ver("2.4.7"))); e.Available ||
		!strings.Contains(e.Problem, "2.4.7 is too old") || e.Install.URL == "" || e.Version != "2.4.7" {
		t.Errorf("too old: %+v", e)
	}
	if e := check(detectEngine(hostInfo{goos: "windows"}, found("", errNotFound), nil)); e.Available || !strings.Contains(e.Problem, "windows") {
		t.Errorf("unsupported OS: %+v", e)
	}
	for _, e := range seen {
		if s := e.Problem + " " + e.Install.Summary(); strings.Contains(strings.ToLower(s), "brew") {
			t.Errorf("Homebrew advice: %q", s)
		}
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

// A binary that runs and fails is broken. The failure is remembered briefly
// — a page polling the engine can't start a process per request — and a
// fix is noticed once that passes, or at once if the binary changes.
func TestVersionProbeRemembersAFailureBriefly(t *testing.T) {
	dir := t.TempDir()
	bin := dir + "/openvpn"
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho x >> \"$0.calls\"\necho 'dyld: Library not loaded: libssl.3.dylib' >&2\nexit 134\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1000, 0)
	c := versionCache{now: func() time.Time { return clock }}
	calls := func() int { b, _ := os.ReadFile(bin + ".calls"); return strings.Count(string(b), "x") }
	fi, _ := os.Stat(bin)
	for range 3 {
		if v, err := c.version(bin, fi); v != "" || err == nil || !strings.Contains(err.Error(), "doesn't run: dyld: Library not loaded") {
			t.Fatalf("got %q, %v", v, err)
		}
	}
	if n := calls(); n != 1 {
		t.Fatalf("a failed probe ran %d times within %s", n, failedProbeFor)
	}
	clock = clock.Add(failedProbeFor)
	_, _ = c.version(bin, fi)
	if n := calls(); n != 2 {
		t.Fatalf("after %s the probe must run again (ran %d times)", failedProbeFor, n)
	}
	// Replaced (a new file, new inode): probed straight away.
	fixed := dir + "/openvpn.new"
	if err := os.WriteFile(fixed, []byte("#!/bin/sh\necho 'OpenVPN 2.6.23 aarch64-apple-darwin'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(fixed, bin); err != nil {
		t.Fatal(err)
	}
	fi, _ = os.Stat(bin)
	if v, err := c.version(bin, fi); v != "2.6.23" || err != nil {
		t.Fatalf("a replaced binary must be probed at once: %q, %v", v, err)
	}
}

// Review finding #9: a binary the probe can't even start is not "available,
// version unknown" — it is not available.
func TestAnUnstartableBinaryIsNotAvailable(t *testing.T) {
	bin := t.TempDir() + "/openvpn"
	if err := os.WriteFile(bin, []byte("not a program"), 0o644); err != nil { // exec: permission denied
		t.Fatal(err)
	}
	fi, _ := os.Stat(bin)
	var c versionCache
	v, err := c.version(bin, fi)
	if v != "" || err == nil || !strings.Contains(err.Error(), "couldn't be checked") {
		t.Fatalf("got %q, %v", v, err)
	}
	e := detectEngine(linuxHost("ID=debian\n"), func() (string, os.FileInfo, error) { return bin, fi, nil }, c.version)
	if e.Available {
		t.Fatalf("an unprobed binary was reported available: %+v", e)
	}
}

// openvpn (and its version probe) get a fixed environment, nothing of the
// daemon's — on macOS, OPENSSL_CONF=/dev/null so no openssl.cnf is read.
func TestProbeRunsWithOpenVPNsOwnEnvironment(t *testing.T) {
	t.Setenv("RIFTROUTE_LEAK_CHECK", "leaked")
	t.Setenv("OPENSSL_CONF", "/tmp/evil.cnf")
	bin := t.TempDir() + "/openvpn"
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nenv > \"$0.env\"\necho 'OpenVPN 2.6.23 x86_64-pc-linux-gnu'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if v, err := probeVersion(bin); v != "2.6.23" || err != nil {
		t.Fatalf("probe: %q, %v", v, err)
	}
	b, _ := os.ReadFile(bin + ".env")
	env := string(b)
	if !strings.Contains(env, "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n") || strings.Contains(env, "leaked") || strings.Contains(env, "evil") {
		t.Fatalf("environment:\n%s", env)
	}
	if got := strings.Contains(env, "OPENSSL_CONF=/dev/null\n"); got != (runtime.GOOS == "darwin") {
		t.Fatalf("OPENSSL_CONF=/dev/null set=%v on %s:\n%s", got, runtime.GOOS, env)
	}
	if got := openvpnEnv("darwin"); len(got) != 2 || got[1] != "OPENSSL_CONF=/dev/null" {
		t.Fatalf("darwin env %v", got)
	}
	if got := openvpnEnv("linux"); len(got) != 1 {
		t.Fatalf("linux env %v (the distribution's openssl.cnf holds the system crypto policy)", got)
	}
}

func TestInstallSummaryReadsAsASentence(t *testing.T) {
	in := &domain.TunnelInstall{Commands: []string{"sudo apt install openvpn"}, Note: "It comes from EPEL."}
	if got := in.Summary(); got != "run `sudo apt install openvpn`. It comes from EPEL." {
		t.Fatalf("got %q", got)
	}
	in = &domain.TunnelInstall{Note: "Enable EPEL first.", URL: "https://example.org"}
	if got := in.Summary(); got != "Enable EPEL first. https://example.org" {
		t.Fatalf("got %q", got)
	}
}
