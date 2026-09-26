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

// failedProbeFor is how long a failed version probe is remembered for the
// same binary: long enough that a page polling GET /tunnels/engine doesn't
// start a process per request, short enough that a fix outside the binary
// (a missing library put back) is noticed soon. A changed binary is probed
// again straight away.
const failedProbeFor = 30 * time.Second

// versionCache remembers the result of probing the binary at a path, keyed
// by the file's identity (path, size, mtime, inode), so the engine can be
// reported on every page load without running openvpn each time.
type versionCache struct {
	mu  sync.Mutex
	key string
	ver string
	err error     // a failed probe: remembered until at+failedProbeFor
	at  time.Time // when err was recorded
	now func() time.Time
}

func (c *versionCache) version(bin string, fi os.FileInfo) (string, error) {
	key := fmt.Sprintf("%s|%d|%d|%d", bin, fi.Size(), fi.ModTime().UnixNano(), fileIno(fi))
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	// Held across the probe: concurrent callers wait for its answer rather
	// than starting their own.
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.key == key && (c.err == nil || now().Sub(c.at) < failedProbeFor) {
		return c.ver, c.err
	}
	ver, err := probeVersion(bin)
	c.key, c.ver, c.err, c.at = key, ver, err, now()
	return ver, err
}

// probeVersion runs `bin --version` as nobody, with openvpn's own
// environment. Anything short of a version (or a clean run that didn't print
// one) means tunnels aren't available: a binary root can't even check is not
// one to run as root.
func probeVersion(bin string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--version")
	cmd.Env = openvpnEnv(runtime.GOOS)
	cmd.Dir = "/"
	cmd.WaitDelay = 2 * time.Second  // a child holding stdout open can't hang us
	unprivileged(cmd)                // reading a version needs no root
	out, err := cmd.CombinedOutput() // some versions exit 1 after printing it
	ver := parseVersion(out)
	var exit *exec.ExitError
	switch {
	case ver != "":
		return ver, nil
	case ctx.Err() != nil:
		return "", fmt.Errorf("%s --version didn't finish", bin)
	case errors.As(err, &exit): // it ran and failed: broken (a missing library, …)
		return "", fmt.Errorf("%s doesn't run: %s", bin, firstLine(out, err))
	case err != nil: // it couldn't even be started (as nobody)
		return "", fmt.Errorf("%s couldn't be checked: %v", bin, err)
	}
	return "", nil // it ran cleanly without saying: openvpn will say what it can't do
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
}

func readHost() hostInfo {
	h := hostInfo{goos: runtime.GOOS}
	if h.goos == "linux" {
		for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
			if data, err := os.ReadFile(p); err == nil {
				h.osRelease = parseOSRelease(data)
				break
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
	var unsafe *unsafeError
	switch {
	case errors.Is(err, errNotFound):
		return domain.TunnelEngine{Problem: "OpenVPN isn't installed", Install: installHelp(h)}
	case errors.As(err, &unsafe): // present, but others could have changed it
		return domain.TunnelEngine{Path: bin, Problem: err.Error(), Install: unsafeHelp(h, unsafe)}
	case err != nil: // present, but it couldn't be checked
		return domain.TunnelEngine{Path: bin, Problem: err.Error(), Install: repairHelp(h, bin, "")}
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

// On macOS the daemon runs only the openvpn that ships with RiftRoute, so the
// fixes are RiftRoute's own, never a package manager's.
const (
	// macUpdate is the fix for a missing one: the daemon's update check
	// installs the one the newest release ships (internal/updater's repair).
	// A daemon that isn't the installed service can't, hence the second way.
	macUpdate = "Tunnels use the openvpn that ships with RiftRoute. Checking for updates installs it: " +
		"`riftroute update check`, or Check for updates on the app's Tunnels page — it works with updates off too. " +
		"Reinstalling the daemon from a current release (`sudo riftroute daemon install`) also puts it in place."
	// macReinstall is the fix for one that's there but can't be used: an
	// update check never replaces an openvpn that's present.
	macReinstall = "Reinstall the daemon from a current release to put back the openvpn that ships with RiftRoute: " +
		"`sudo riftroute daemon install`, or in the app, Settings → Daemon service: Uninstall, then Install & start."
)

// releasesURL is where a release that includes openvpn comes from.
const releasesURL = "https://github.com/Amirhat/riftroute/releases/latest"

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

// newHelp starts the steps for this system, with the kind of fix that
// applies here when openvpn is missing (missing) or present but unusable.
func newHelp(h hostInfo, missing bool) *domain.TunnelInstall {
	in := &domain.TunnelInstall{System: systemName(h)}
	switch {
	case h.goos == "darwin" && missing:
		in.Action = domain.TunnelInstallUpdate
	case h.goos == "darwin":
		in.Action = domain.TunnelInstallReinstall
	case h.goos == "linux":
		in.Action = domain.TunnelInstallPackage
	}
	return in
}

// installHelp is how to install openvpn on this system.
func installHelp(h hostInfo) *domain.TunnelInstall {
	in := newHelp(h, true)
	switch h.goos {
	case "darwin":
		in.Note, in.URL = macUpdate, releasesURL
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
	in := newHelp(h, false)
	if h.goos == "darwin" {
		in.Note, in.URL = macReinstall, releasesURL
		return in
	}
	in.Note = fmt.Sprintf("This system's openvpn package is older than %d.%d: upgrade the system, or install a newer "+
		"openvpn from OpenVPN's own packages.", minMajor, minMinor)
	in.URL = "https://openvpn.net/community/"
	return in
}

// unsafeHelp is how to fix an openvpn that someone other than root could have
// changed: reinstall it, don't just fix the permissions — it may have been
// replaced already.
func unsafeHelp(h hostInfo, u *unsafeError) *domain.TunnelInstall {
	const replaced = "Other users could have changed it, so reinstall it rather than just fixing the permissions."
	if h.goos == "linux" && u.Path != u.Bin {
		// A package reinstall doesn't fix the folder.
		in := repairHelp(h, u.Bin, "")
		in.Note = strings.TrimSpace(fmt.Sprintf("Make %s owned by root and writable only by root, then reinstall openvpn: "+
			"other users could have replaced it. %s", u.Path, in.Note))
		return in
	}
	if h.goos == "linux" && strings.Contains(u.Why, "owned") {
		return repairHelp(h, u.Bin, "openvpn must belong to root: reinstall the package so it does. "+replaced)
	}
	return repairHelp(h, u.Bin, replaced)
}

// repairHelp is how to replace a broken or tampered openvpn at bin.
func repairHelp(h hostInfo, bin, why string) *domain.TunnelInstall {
	in := newHelp(h, false)
	in.Note = why
	switch h.goos {
	case "darwin":
		in.Note, in.URL = strings.TrimSpace(why+" "+macReinstall), releasesURL
	case "linux":
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
