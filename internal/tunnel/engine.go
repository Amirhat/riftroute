package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// ErrEngineUnavailable means openvpn can't run tunnels here: it isn't
// installed, is too old, or is unsafe to run as root. The error carrying it
// is an *EngineError with the install help.
var ErrEngineUnavailable = errors.New("OpenVPN isn't usable")

// EngineError is why a tunnel can't start; it carries the engine report so
// callers can show the install steps.
type EngineError struct{ Engine domain.TunnelEngine }

func (e *EngineError) Error() string {
	if h := e.Engine.Install.Summary(); h != "" {
		return e.Engine.Problem + " — " + h
	}
	return e.Engine.Problem
}

func (e *EngineError) Unwrap() error { return ErrEngineUnavailable }

// minMajor.minMinor is the oldest openvpn tunnels run on: the rendered config
// uses data-ciphers and data-ciphers-fallback, which 2.5 introduced.
const minMajor, minMinor = 2, 5

var reVersion = regexp.MustCompile(`OpenVPN (\d+)\.(\d+)(?:\.\d+)?(?:_[A-Za-z0-9]+)?`)

// supportedOS lists where the daemon runs tunnels (where RiftRoute runs).
func supportedOS(goos string) bool { return goos == "darwin" || goos == "linux" }

// versionCache remembers the version of the binary at a path, keyed by the
// file's identity, so the engine can be reported on every page load without
// running openvpn each time.
type versionCache struct {
	mu  sync.Mutex
	key string
	ver string
}

func (c *versionCache) version(bin string, fi os.FileInfo) (string, error) {
	key := fmt.Sprintf("%s|%d|%d", bin, fi.Size(), fi.ModTime().UnixNano())
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.key == key {
		return c.ver, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--version")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Dir = "/"
	cmd.WaitDelay = 2 * time.Second  // a child holding stdout open can't hang us
	unprivileged(cmd)                // reading a version needs no root
	out, err := cmd.CombinedOutput() // some versions exit 1 after printing it
	ver := parseVersion(out)
	var exit *exec.ExitError
	switch {
	case ver != "":
	case ctx.Err() != nil:
		return "", fmt.Errorf("%s --version didn't finish", bin)
	case errors.As(err, &exit): // it ran and failed: broken (a missing library, …)
		return "", fmt.Errorf("%s doesn't run: %s", bin, firstLine(out, err))
	case err != nil: // couldn't be started as nobody: unknown, not broken
		return "", nil
	}
	c.key, c.ver = key, ver // only a successful probe is remembered
	return ver, nil
}

func firstLine(out []byte, err error) string {
	if l, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n"); l != "" {
		return l
	}
	return err.Error()
}

// parseVersion extracts "2.6.14" from `openvpn --version` output.
func parseVersion(out []byte) string {
	m := reVersion.Find(out)
	if m == nil {
		return ""
	}
	return strings.TrimPrefix(string(m), "OpenVPN ")
}

// tooOld reports a parsed version older than minMajor.minMinor. An unknown
// version is not "too old": openvpn itself will say what it can't do.
func tooOld(ver string) bool {
	m := reVersion.FindStringSubmatch("OpenVPN " + ver)
	if m == nil {
		return false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return major < minMajor || (major == minMajor && minor < minMinor)
}

// hostInfo is what the install help depends on, read from this machine.
type hostInfo struct {
	goos      string
	osRelease map[string]string // /etc/os-release on Linux
	brew      bool              // Homebrew is installed (macOS)
}

func readHost() hostInfo {
	h := hostInfo{goos: runtime.GOOS}
	switch h.goos {
	case "linux":
		for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
			if data, err := os.ReadFile(p); err == nil {
				h.osRelease = parseOSRelease(data)
				break
			}
		}
	case "darwin":
		for _, p := range []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"} {
			if _, err := os.Stat(p); err == nil {
				h.brew = true
			}
		}
	}
	return h
}

// parseOSRelease reads os-release(5) KEY=value lines (values may be quoted).
func parseOSRelease(data []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		if uq, err := strconv.Unquote(v); err == nil {
			v = uq
		} else {
			v = strings.Trim(v, `"'`)
		}
		out[k] = v
	}
	return out
}

// detectEngine reports whether openvpn can run tunnels on this machine.
func detectEngine(h hostInfo, find func() (string, os.FileInfo, error), versionOf func(string, os.FileInfo) (string, error)) domain.TunnelEngine {
	if !supportedOS(h.goos) {
		return domain.TunnelEngine{Problem: "tunnels aren't supported on " + h.goos}
	}
	bin, fi, err := find()
	switch {
	case errors.Is(err, errNotFound):
		return domain.TunnelEngine{Problem: "OpenVPN isn't installed", Install: installHelp(h)}
	case err != nil: // present but unsafe to run as root
		return domain.TunnelEngine{Path: bin, Problem: err.Error(), Install: repairHelp(h, bin,
			"Other users could have changed it, so reinstall it rather than just fixing the permissions.")}
	}
	e := domain.TunnelEngine{Path: bin}
	if e.Version, err = versionOf(bin, fi); err != nil {
		e.Problem, e.Install = err.Error(), repairHelp(h, bin, "")
		return e
	}
	if tooOld(e.Version) {
		e.Problem = fmt.Sprintf("OpenVPN %s is too old — tunnels need %d.%d or newer", e.Version, minMajor, minMinor)
		e.Install = upgradeHelp(h, bin)
		return e
	}
	e.Available = true
	return e
}

// connectNote is appended wherever the OpenVPN Connect app might be mistaken
// for what RiftRoute needs.
const connectNote = "The OpenVPN Connect app doesn't include the openvpn program RiftRoute runs."

// linuxInstall maps os-release IDs to install steps. IDs are matched in
// os-release order (ID, then each ID_LIKE), so a derivative falls back to
// the distribution it is based on.
var linuxInstall = []struct {
	ids       []string
	cmds      []string
	reinstall string
	note      string
	url       string
}{
	{ids: []string{"debian", "ubuntu"}, cmds: []string{"sudo apt install openvpn"}, reinstall: "sudo apt install --reinstall openvpn"},
	// openvpn isn't in these distributions' own repositories in a form one
	// command installs; the generic note beats a wrong command.
	{ids: []string{"ol", "amzn"}},
	{ids: []string{"rocky", "almalinux", "centos"}, cmds: []string{"sudo dnf install epel-release", "sudo dnf install openvpn"},
		reinstall: "sudo dnf reinstall openvpn", note: "OpenVPN comes from EPEL on this system."},
	{ids: []string{"rhel"}, cmds: []string{"sudo dnf install openvpn"}, reinstall: "sudo dnf reinstall openvpn",
		note: "OpenVPN comes from EPEL on RHEL: enable EPEL first.", url: "https://docs.fedoraproject.org/en-US/epel/"},
	{ids: []string{"fedora"}, cmds: []string{"sudo dnf install openvpn"}, reinstall: "sudo dnf reinstall openvpn"},
	{ids: []string{"arch"}, cmds: []string{"sudo pacman -S openvpn"}, reinstall: "sudo pacman -S openvpn"},
	{ids: []string{"opensuse", "opensuse-leap", "opensuse-tumbleweed", "suse", "sles"}, cmds: []string{"sudo zypper install openvpn"},
		reinstall: "sudo zypper install --force openvpn"},
	{ids: []string{"alpine"}, cmds: []string{"sudo apk add openvpn"}, reinstall: "sudo apk fix openvpn"},
	{ids: []string{"void"}, cmds: []string{"sudo xbps-install -S openvpn"}, reinstall: "sudo xbps-install -f openvpn"},
	{ids: []string{"gentoo"}, cmds: []string{"sudo emerge --ask net-vpn/openvpn"}, reinstall: "sudo emerge --ask --oneshot net-vpn/openvpn"},
}

// linuxEntry is the install table entry for this distribution, if any.
func linuxEntry(h hostInfo) (int, bool) {
	ids := append([]string{h.osRelease["ID"]}, strings.Fields(h.osRelease["ID_LIKE"])...)
	for _, id := range ids {
		for i, d := range linuxInstall {
			if id != "" && slices.Contains(d.ids, id) {
				return i, true
			}
		}
	}
	return 0, false
}

var genericLinuxNote = fmt.Sprintf("Install the openvpn package (%d.%d or newer) with your distribution's package manager.", minMajor, minMinor)

// isHomebrew reports a binary Homebrew installed (it lives in the Cellar).
func isHomebrew(bin string) bool { return strings.Contains(bin, "/Cellar/") }

func systemName(h hostInfo) string {
	switch h.goos {
	case "darwin":
		return "macOS"
	case "linux":
		for _, k := range []string{"PRETTY_NAME", "NAME"} {
			if v := h.osRelease[k]; v != "" {
				return v
			}
		}
		return "Linux"
	}
	return h.goos
}

// installHelp is how to install openvpn on this system.
func installHelp(h hostInfo) *domain.TunnelInstall {
	in := &domain.TunnelInstall{System: systemName(h)}
	switch h.goos {
	case "darwin":
		in.Commands = []string{"brew install openvpn"}
		in.Note = connectNote
		if !h.brew {
			in.Note = "Needs Homebrew — install it from brew.sh first. " + connectNote
			in.URL = "https://brew.sh"
		}
	case "linux":
		if i, ok := linuxEntry(h); ok && len(linuxInstall[i].cmds) > 0 {
			d := linuxInstall[i]
			in.Commands, in.Note, in.URL = d.cmds, d.note, d.url
			return in
		}
		in.Note = genericLinuxNote
	}
	return in
}

// upgradeHelp is how to get a new enough openvpn when the one at bin is too
// old.
func upgradeHelp(h hostInfo, bin string) *domain.TunnelInstall {
	in := &domain.TunnelInstall{System: systemName(h)}
	if h.goos == "darwin" {
		if isHomebrew(bin) {
			in.Commands = []string{"brew upgrade openvpn"}
			return in
		}
		// Homebrew's paths are searched first, so installing it there wins.
		in = installHelp(h)
		in.Note = strings.TrimSpace(fmt.Sprintf("RiftRoute uses Homebrew's openvpn ahead of %s. %s", bin, in.Note))
		return in
	}
	in.Note = fmt.Sprintf("This system's openvpn package is older than %d.%d: upgrade the system, or install a newer "+
		"openvpn from OpenVPN's own packages.", minMajor, minMinor)
	in.URL = "https://openvpn.net/community/"
	return in
}

// repairHelp is how to replace a broken or tampered openvpn at bin.
func repairHelp(h hostInfo, bin, why string) *domain.TunnelInstall {
	in := &domain.TunnelInstall{System: systemName(h), Note: why}
	switch {
	case h.goos == "darwin" && isHomebrew(bin):
		in.Commands = []string{"brew reinstall openvpn"}
	case h.goos == "linux":
		if i, ok := linuxEntry(h); ok && linuxInstall[i].reinstall != "" {
			in.Commands = []string{linuxInstall[i].reinstall}
			break
		}
		fallthrough
	default:
		in.Note = strings.TrimSpace("Reinstall openvpn (" + bin + ") with the tool that installed it. " + why)
	}
	return in
}
