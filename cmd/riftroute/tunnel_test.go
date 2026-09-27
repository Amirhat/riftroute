package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/Amirhat/riftroute/internal/api"
	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/store"
	"github.com/Amirhat/riftroute/internal/tunnel"
)

const (
	loginProfile = "client\ndev tun\nremote 192.0.2.1 1194 udp\nauth-user-pass\n<ca>\nCA\n</ca>\n"
	plainProfile = "client\ndev tun\nremote 192.0.2.1 1194 udp\n<ca>\nCA\n</ca>\n"
)

// tunnelDaemon runs the real API server and tunnel manager on a throwaway
// socket. openvpn is the fake launcher, which speaks the real management
// protocol, so connects run end to end without root or a network change.
func tunnelDaemon(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rr") // short: unix socket paths cap at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	prov := fake.New()
	svc := core.New(prov, st, "test")
	proto := safety.NewProtocol(prov, st, safety.RealClock{}, nil, "fake", nil)
	srv := api.NewServer(svc, st, proto, uint32(os.Getuid()), "test", nil)
	m, err := tunnel.New(tunnel.Options{
		Dir: filepath.Join(dir, "tunnels"),
		Launcher: &tunnel.FakeLauncher{
			OnUp:   func(iface, ip string) { prov.SetTunnelIface(iface, ip, true) },
			OnDown: func(iface, ip string) { prov.SetTunnelIface(iface, ip, false) },
		},
		Ifaces: prov.Interfaces,
		Apply:  func(context.Context) error { return nil },
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.SetTunnels(m)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() {
		m.Shutdown()
		cancel()
		_ = ln.Close()
		<-done
		_ = st.Close()
	})
	return sock
}

// runCLI runs the command line against the daemon on sock, with stdin piped
// in, and returns what it wrote to stdout and stderr.
func runCLI(t *testing.T, sock, stdin string, args ...string) (string, string, error) {
	t.Helper()
	root := rootCmd()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(append([]string{"--socket", sock}, args...))
	err := root.ExecuteContext(context.Background())
	return out.String(), errb.String(), err
}

// oneJSON decodes stdout into v and fails unless it is exactly one JSON
// document, with nothing before or after it.
func oneJSON(t *testing.T, stdout string, v any) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(stdout))
	if err := dec.Decode(v); err != nil {
		t.Fatalf("stdout isn't a JSON document: %v\n%s", err, stdout)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		t.Fatalf("stdout carries more than one JSON document:\n%s", stdout)
	}
}

func writeProfile(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "office.ovpn")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// `add --connect --json` used to print "saved tunnel …" and then the JSON.
func TestTunnelAddConnectJSONIsOneDocument(t *testing.T) {
	sock := tunnelDaemon(t)
	out, errOut, err := runCLI(t, sock, "pw\n", "tunnel", "add", "infra", writeProfile(t, loginProfile),
		"--username", "alice", "--password-stdin", "--route", "10.20.0.0/24", "--connect", "--json")
	if err != nil {
		t.Fatalf("add: %v\n%s", err, errOut)
	}
	var st domain.TunnelStatus
	oneJSON(t, out, &st)
	if st.Name != "infra" || st.State != domain.TunnelConnected || !st.HasPassword {
		t.Fatalf("status = %+v", st)
	}
	if !strings.Contains(errOut, "saved tunnel infra") {
		t.Errorf("the human summary belongs on stderr under --json; stderr:\n%s", errOut)
	}
}

func TestTunnelCommandsPrintOnlyJSONUnderJSON(t *testing.T) {
	sock := tunnelDaemon(t)
	profile := writeProfile(t, plainProfile)
	var st domain.TunnelStatus

	out, errOut, err := runCLI(t, sock, "", "tunnel", "add", "infra", profile, "--route", "10.20.0.0/24", "--json")
	if err != nil {
		t.Fatalf("add: %v\n%s", err, errOut)
	}
	oneJSON(t, out, &st)
	if st.State != domain.TunnelDisconnected {
		t.Fatalf("add: %+v", st)
	}

	out, errOut, err = runCLI(t, sock, "", "tunnel", "edit", "infra", "--route", "10.30.0.0/24", "--connect", "--json")
	if err != nil {
		t.Fatalf("edit: %v\n%s", err, errOut)
	}
	oneJSON(t, out, &st)
	if st.State != domain.TunnelConnected || strings.Join(st.Routes, ",") != "10.30.0.0/24" {
		t.Fatalf("edit --connect: %+v", st)
	}

	out, errOut, err = runCLI(t, sock, "", "tunnel", "down", "infra", "--json")
	if err != nil {
		t.Fatalf("down: %v\n%s", err, errOut)
	}
	oneJSON(t, out, &st)

	out, errOut, err = runCLI(t, sock, "", "tunnel", "up", "infra", "--no-wait", "--json")
	if err != nil {
		t.Fatalf("up --no-wait: %v\n%s", err, errOut)
	}
	st = domain.TunnelStatus{}
	oneJSON(t, out, &st)
	if st.Name != "infra" || st.State == domain.TunnelDisconnected {
		t.Fatalf("up --no-wait: %+v", st)
	}

	out, errOut, err = runCLI(t, sock, "", "tunnel", "rm", "infra", "--json")
	if err != nil {
		t.Fatalf("rm: %v\n%s", err, errOut)
	}
	var del map[string]string
	oneJSON(t, out, &del)
	if del["status"] != "deleted" || del["name"] != "infra" {
		t.Fatalf("rm: %v", del)
	}
}

// Without --json the summary stays on stdout, where people read it.
func TestTunnelAddWithoutJSONPrintsSummary(t *testing.T) {
	sock := tunnelDaemon(t)
	out, errOut, err := runCLI(t, sock, "", "tunnel", "add", "infra", writeProfile(t, plainProfile), "--route", "10.20.0.0/24")
	if err != nil {
		t.Fatalf("add: %v\n%s", err, errOut)
	}
	if !strings.Contains(out, "saved tunnel infra") || !strings.Contains(out, "routes: 10.20.0.0/24") {
		t.Fatalf("stdout:\n%s", out)
	}
}

// Typed on a terminal, --password-stdin would echo the password: refused
// before anything else happens, pointing at the hidden prompt instead.
func TestTunnelPasswordStdinRefusedOnTerminal(t *testing.T) {
	old := stdinTerminal
	stdinTerminal = func(io.Reader) (int, bool) { return -1, true }
	t.Cleanup(func() { stdinTerminal = old })
	noDaemon := filepath.Join(t.TempDir(), "none.sock") // reaching it would fail differently

	for _, args := range [][]string{
		{"tunnel", "add", "infra", writeProfile(t, loginProfile), "--password-stdin"},
		{"tunnel", "edit", "infra", "--password-stdin"},
	} {
		_, _, err := runCLI(t, noDaemon, "", args...)
		if !errors.Is(err, errUsage) || !strings.Contains(err.Error(), "without echo") {
			t.Errorf("%s: got %v", strings.Join(args[:2], " "), err)
		}
	}
}

func TestTunnelPasswordStdinWarnsWhenProfileHasNoLogin(t *testing.T) {
	sock := tunnelDaemon(t)
	_, errOut, err := runCLI(t, sock, "pw\n", "tunnel", "add", "infra", writeProfile(t, plainProfile),
		"--route", "10.20.0.0/24", "--password-stdin")
	if err != nil {
		t.Fatalf("add: %v\n%s", err, errOut)
	}
	if !strings.Contains(errOut, "warning: this profile doesn't log in with a username and password; --password-stdin is ignored") {
		t.Errorf("add stderr:\n%s", errOut)
	}

	_, errOut, err = runCLI(t, sock, "pw\n", "tunnel", "edit", "infra", "--password-stdin")
	if err != nil {
		t.Fatalf("edit: %v\n%s", err, errOut)
	}
	if !strings.Contains(errOut, "--password-stdin is ignored") {
		t.Errorf("edit stderr:\n%s", errOut)
	}
}

// A password flag value would land in shell history and the process list.
func TestTunnelPasswordIsNeverAFlagValue(t *testing.T) {
	for name, flags := range map[string]*pflag.FlagSet{"add": tunnelAddCmd().Flags(), "edit": tunnelEditCmd().Flags()} {
		if flags.Lookup("password") != nil {
			t.Errorf("%s has a --password flag", name)
		}
		flags.VisitAll(func(f *pflag.Flag) {
			if strings.Contains(f.Name, "password") && f.Value.Type() != "bool" {
				t.Errorf("%s --%s takes a %s value", name, f.Name, f.Value.Type())
			}
		})
	}
}

// A wg-quick file imports as a WireGuard tunnel: its DNS is reported as
// ignored, its AllowedIPs never become routes, and a login is refused.
// Its profile can only be replaced by another WireGuard configuration.
func TestTunnelAddWireGuard(t *testing.T) {
	sock := tunnelDaemon(t)
	k := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	conf := filepath.Join(t.TempDir(), "lab-wg0.conf")
	text := "[Interface]\nPrivateKey = " + k(1) + "\nAddress = 10.64.0.2/32\nDNS = 10.64.0.1\n" +
		"[Peer]\nPublicKey = " + k(2) + "\nEndpoint = 198.51.100.7:51820\nAllowedIPs = 0.0.0.0/0\n"
	if err := os.WriteFile(conf, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, sock, "", "tunnel", "add", "lab", conf, "--username", "alice"); err == nil ||
		!strings.Contains(err.Error(), "no username or password") {
		t.Fatalf("a login for WireGuard: %v", err)
	}
	out, errOut, err := runCLI(t, sock, "", "tunnel", "add", "lab", conf, "--route", "10.20.0.0/16")
	if err != nil {
		t.Fatalf("add: %v\n%s", err, errOut)
	}
	if !strings.Contains(out, "saved tunnel lab (wireguard: 198.51.100.7:51820/udp") || !strings.Contains(out, "ignored from the configuration (RiftRoute handles these): DNS") {
		t.Fatalf("stdout:\n%s", out)
	}
	if strings.Contains(errOut, "OpenVPN") {
		t.Errorf("a WireGuard tunnel was warned about openvpn:\n%s", errOut)
	}
	out, _, err = runCLI(t, sock, "", "tunnel", "list")
	if err != nil || !strings.Contains(out, "wireguard") || !strings.Contains(out, "10.20.0.0/16") || strings.Contains(out, "0.0.0.0/0") {
		t.Fatalf("list: %v\n%s", err, out)
	}
	if _, _, err := runCLI(t, sock, "", "tunnel", "edit", "lab", "--profile", writeProfile(t, plainProfile)); err == nil ||
		!strings.Contains(err.Error(), "WireGuard configuration") {
		t.Fatalf("an .ovpn for a WireGuard tunnel: %v", err)
	}
}
