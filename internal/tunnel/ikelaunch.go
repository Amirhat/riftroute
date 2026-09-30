package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/strongswan/govici/vici"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/platform"
)

// IKEv2 tunnels run strongSwan's charon-cmd, one process per session (see
// docs/tunnels-ikev2.md): it negotiates the connection, carries its traffic
// through a TUN (kernel-libipsec) and is followed over its VICI socket.

// IKESpec is what an IKELauncher starts.
type IKESpec struct {
	Name   string       // tunnel name, for logs
	Args   []string     // charon-cmd's arguments (renderIKE)
	Conf   string       // its strongswan.conf
	Socket string       // the VICI socket that config names
	Config *IKEv2Config // the profile (the fake reads it)
}

// IKEStatus is a session's connection as charon reports it.
type IKEStatus struct {
	// State is the IKE_SA's (CONNECTING, ESTABLISHED, …); "" when there's
	// none.
	State string
	// Up: established, with a CHILD_SA installed — traffic flows.
	Up bool
	// VIPs are the addresses the server assigned (on the TUN).
	VIPs    []netip.Addr
	Server  netip.AddrPort
	In, Out uint64
}

// IKEProcess is a running charon-cmd.
type IKEProcess interface {
	Process
	// Status reads the connection's state (VICI list-sas).
	Status(ctx context.Context) (IKEStatus, error)
	// Stop asks it to shut down cleanly: it deletes the connection with the
	// server, and exits.
	Stop() error
}

// IKELauncher starts charon-cmd sessions.
type IKELauncher interface {
	// Engine reports whether IKEv2 connections can run here, and if not,
	// how the user installs what's missing.
	Engine() domain.TunnelEngine
	Start(spec IKESpec) (IKEProcess, error)
}

// ikeCandidates are the only places the daemon runs charon-cmd from: on
// macOS the one that ships with RiftRoute (built to leave routing to the
// engine: packaging/strongswan), on Linux the distribution's — by the rules
// binaryCandidates gives for openvpn.
func ikeCandidates(goos string) []string {
	switch goos {
	case "darwin":
		if p := platform.InstalledCharonCmdPath(); p != "" {
			return []string{p}
		}
	case "linux":
		return []string{"/usr/sbin/charon-cmd", "/usr/bin/charon-cmd", "/sbin/charon-cmd"}
	}
	return nil
}

// ikeEnv is the whole environment charon-cmd runs with (as root, and as
// nobody for the version probe): its own strongswan.conf, and, on macOS,
// no openssl.cnf ever read (see openvpnEnv).
func ikeEnv(goos, conf string) []string {
	return append(openvpnEnv(goos), "STRONGSWAN_CONF="+conf)
}

// ikeMinMajor.ikeMinMinor is the oldest strongSwan IKEv2 tunnels run on.
const ikeMinMajor, ikeMinMinor = 5, 9

var reIKEVersion = regexp.MustCompile(`strongSwan (\d+)\.(\d+)(?:\.\d+)?`)

// probeIKEVersion runs `charon-cmd --version` as nobody: it prints the version
// before reading any configuration or loading anything.
func probeIKEVersion(bin string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--version")
	cmd.Env = ikeEnv(runtime.GOOS, os.DevNull)
	cmd.Dir = "/"
	cmd.WaitDelay = 2 * time.Second
	unprivileged(cmd)
	out, err := cmd.CombinedOutput()
	if m := reIKEVersion.FindSubmatch(out); m != nil {
		return strings.TrimPrefix(string(m[0]), "strongSwan "), nil
	}
	switch {
	case ctx.Err() != nil:
		return "", fmt.Errorf("%s --version didn't finish", bin)
	case err != nil:
		return "", fmt.Errorf("%s doesn't run: %s", bin, firstLine(out, err))
	}
	return "", fmt.Errorf("%s --version didn't say which strongSwan it is", bin)
}

func ikeTooOld(ver string) bool {
	m := reIKEVersion.FindStringSubmatch("strongSwan " + ver)
	if m == nil {
		return false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return major < ikeMinMajor || (major == ikeMinMajor && minor < ikeMinMinor)
}

// detectIKEEngine reports whether charon-cmd can run IKEv2 tunnels here.
func detectIKEEngine(h hostInfo, find func() (string, fs.FileInfo, error), versionOf func(string, fs.FileInfo) (string, error)) domain.TunnelEngine {
	if !supportedOS(h.goos) {
		return domain.TunnelEngine{Problem: "IKEv2 tunnels aren't supported on " + h.goos}
	}
	bin, fi, err := find()
	switch {
	case errors.Is(err, errNotFound):
		return domain.TunnelEngine{Problem: "IKEv2 tunnels run on strongSwan's charon-cmd, which isn't installed", Install: ikeHelp(h, true)}
	case err != nil: // present, but unsafe to run as root or not checkable
		return domain.TunnelEngine{Path: bin, Problem: err.Error(), Install: ikeHelp(h, false)}
	}
	e := domain.TunnelEngine{Path: bin}
	if e.Version, err = versionOf(bin, fi); err != nil {
		e.Problem, e.Install = err.Error(), ikeHelp(h, false)
		return e
	}
	if ikeTooOld(e.Version) {
		e.Problem = fmt.Sprintf("strongSwan %s is too old — IKEv2 tunnels need %d.%d or newer", e.Version, ikeMinMajor, ikeMinMinor)
		e.Install = ikeHelp(h, false)
		return e
	}
	e.Available = true
	return e
}

const (
	ikeMacUpdate = "IKEv2 tunnels use the strongSwan client (charon-cmd) that ships with RiftRoute. Checking for " +
		"updates installs it: `riftroute update check`, or Check for updates on the app's Tunnels page — it works with " +
		"updates off too. Reinstalling the daemon from a current release (`sudo riftroute daemon install`) also puts it in place."
	ikeMacReinstall = "Reinstall the daemon from a current release to put back the strongSwan client that ships with " +
		"RiftRoute: `sudo riftroute daemon install`, or in the app, Settings → Daemon service: Uninstall, then Install & start."
	ikeLinuxNote = "Install strongSwan's charon-cmd (5.9 or newer) with its kernel-libipsec and vici plugins, from your " +
		"distribution's packages."
)

// ikeLinuxInstall: what installs charon-cmd and the plugins a session loads,
// per distribution (matched like linuxInstall).
var ikeLinuxInstall = []struct {
	ids                []string
	install, reinstall string
	note               string
}{
	{ids: []string{"debian", "ubuntu"}, install: "sudo apt install charon-cmd libcharon-extra-plugins",
		reinstall: "sudo apt install --reinstall charon-cmd libcharon-extra-plugins"},
	// kernel-libipsec is a package of its own there.
	{ids: []string{"fedora"}, install: "sudo dnf install strongswan strongswan-libipsec",
		reinstall: "sudo dnf reinstall strongswan strongswan-libipsec"},
	{ids: []string{"rhel", "rocky", "almalinux", "centos"}, install: "sudo dnf install strongswan strongswan-libipsec",
		reinstall: "sudo dnf reinstall strongswan strongswan-libipsec", note: "strongSwan comes from EPEL on this system: enable EPEL first."},
	{ids: []string{"arch"}, install: "sudo pacman -S strongswan", reinstall: "sudo pacman -S strongswan"},
	{ids: []string{"opensuse", "opensuse-leap", "opensuse-tumbleweed", "suse", "sles"}, install: "sudo zypper install strongswan",
		reinstall: "sudo zypper install --force strongswan"},
	{ids: []string{"alpine"}, install: "sudo apk add strongswan", reinstall: "sudo apk fix strongswan"},
}

// ikeHelp is how to install charon-cmd (missing) or put back a usable one.
func ikeHelp(h hostInfo, missing bool) *domain.TunnelInstall {
	in := newHelp(h, missing)
	switch h.goos {
	case "darwin":
		in.Note, in.URL = ikeMacReinstall, releasesURL
		if missing {
			in.Note = ikeMacUpdate
		}
	case "linux":
		ids := append([]string{h.osRelease["ID"]}, strings.Fields(h.osRelease["ID_LIKE"])...)
		for _, id := range ids {
			for _, d := range ikeLinuxInstall {
				if id != "" && slices.Contains(d.ids, id) {
					in.Commands, in.Note = []string{d.reinstall}, d.note
					if missing {
						in.Commands = []string{d.install}
					}
					return in
				}
			}
		}
		in.Note = ikeLinuxNote
	}
	return in
}

// ExecIKELauncher runs the real charon-cmd — only one ikeCandidates holds and
// rootOwned accepts.
type ExecIKELauncher struct {
	// Output receives each line charon-cmd prints; may be nil.
	Output func(tunnel, line string)
	vc     versionCache
}

// Engine implements IKELauncher; it looks again on every call.
func (l *ExecIKELauncher) Engine() domain.TunnelEngine {
	e, _ := l.engine()
	return e
}

func (l *ExecIKELauncher) engine() (domain.TunnelEngine, fs.FileInfo) {
	bin, fi, err := findIn(ikeCandidates(runtime.GOOS), lstatOwner)
	e := detectIKEEngine(readHost(), func() (string, fs.FileInfo, error) { return bin, fi, err },
		func(bin string, fi fs.FileInfo) (string, error) { return l.vc.versionBy(bin, fi, probeIKEVersion) })
	return e, fi
}

// Start implements IKELauncher.
func (l *ExecIKELauncher) Start(spec IKESpec) (IKEProcess, error) {
	e, fi := l.engine()
	if !e.Available {
		return nil, &EngineError{Engine: e}
	}
	if err := sameFileAsChecked(e.Path, fi); err != nil {
		return nil, err
	}
	cmd := exec.Command(e.Path, spec.Args...)
	cmd.Env = ikeEnv(runtime.GOOS, spec.Conf)
	cmd.Dir = "/"
	ownProcessGroup(cmd)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		return nil, fmt.Errorf("start charon-cmd: %w", err)
	}
	p := &ikeProcess{execProcess: execProcess{cmd: cmd, done: make(chan struct{})}, socket: spec.Socket}
	go readLines(pr, maxOutputLine, func(s string) {
		p.push(s)
		if l.Output != nil {
			l.Output(spec.Name, s)
		}
	})
	go func() {
		p.err = cmd.Wait()
		_ = pw.Close()
		close(p.done)
		p.closeVICI()
	}()
	return p, nil
}

type ikeProcess struct {
	execProcess
	socket string

	vmu sync.Mutex
	vs  *vici.Session
}

// errIKENotRunning: the process has exited.
var errIKENotRunning = errors.New("charon-cmd isn't running")

func (p *ikeProcess) Stop() error { return p.cmd.Process.Signal(syscall.SIGTERM) }

func (p *ikeProcess) Status(ctx context.Context) (IKEStatus, error) {
	select {
	case <-p.done:
		return IKEStatus{}, errIKENotRunning
	default:
	}
	p.vmu.Lock()
	defer p.vmu.Unlock()
	if p.vs == nil {
		// Not there until charon-cmd has loaded its plugins.
		s, err := vici.NewSession(vici.WithSocketPath(p.socket))
		if err != nil {
			return IKEStatus{}, err
		}
		p.vs = s
	}
	in := vici.NewMessage()
	_ = in.Set("noblock", "yes") // an SA busy in an exchange is listed as it is, not waited for
	var sas []*vici.Message
	for m, err := range p.vs.CallStreaming(ctx, "list-sas", "list-sa", in) {
		if err != nil {
			_ = p.vs.Close()
			p.vs = nil
			return IKEStatus{}, err
		}
		sas = append(sas, m)
	}
	return parseSAs(sas), nil
}

func (p *ikeProcess) closeVICI() {
	p.vmu.Lock()
	defer p.vmu.Unlock()
	if p.vs != nil {
		_ = p.vs.Close()
		p.vs = nil
	}
}

// parseSAs reads list-sas' list-sa events: one IKE_SA each, keyed by its
// connection's name. A session has one; while it's rekeyed there are
// briefly two, and the one that's up is the one reported.
func parseSAs(msgs []*vici.Message) IKEStatus {
	var out IKEStatus
	for _, m := range msgs {
		for _, name := range m.Keys() {
			sa, ok := m.Get(name).(*vici.Message)
			if !ok {
				continue
			}
			st := IKEStatus{State: viciString(sa, "state")}
			installed := false
			if children, ok := sa.Get("child-sas").(*vici.Message); ok {
				for _, k := range children.Keys() {
					c, ok := children.Get(k).(*vici.Message)
					if !ok {
						continue
					}
					switch viciString(c, "state") {
					case "INSTALLED", "REKEYING", "REKEYED":
						installed = true
						st.In += viciUint(c, "bytes-in")
						st.Out += viciUint(c, "bytes-out")
					}
				}
			}
			st.Up = (st.State == "ESTABLISHED" || st.State == "REKEYING" || st.State == "REKEYED") && installed
			if vips, ok := sa.Get("local-vips").([]string); ok {
				for _, v := range vips {
					if a, err := netip.ParseAddr(v); err == nil {
						st.VIPs = append(st.VIPs, a.Unmap())
					}
				}
			}
			if a, err := netip.ParseAddr(viciString(sa, "remote-host")); err == nil {
				port, _ := strconv.ParseUint(viciString(sa, "remote-port"), 10, 16)
				st.Server = netip.AddrPortFrom(a.Unmap(), uint16(port))
			}
			if out.State == "" || (st.Up && !out.Up) {
				out = st
			}
		}
	}
	return out
}

func viciString(m *vici.Message, key string) string {
	s, _ := m.Get(key).(string)
	return s
}

func viciUint(m *vici.Message, key string) uint64 {
	n, _ := strconv.ParseUint(viciString(m, key), 10, 64)
	return n
}
