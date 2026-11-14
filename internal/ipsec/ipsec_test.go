package ipsec

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/strongswan/govici/vici"
)

var server = netip.MustParseAddr("203.0.113.9")

func sub(t *testing.T, m *vici.Message, keys ...string) *vici.Message {
	t.Helper()
	for _, k := range keys {
		n, ok := m.Get(k).(*vici.Message)
		if !ok {
			t.Fatalf("no section %q in %s", k, m)
		}
		m = n
	}
	return m
}

func TestConnMessagePSK(t *testing.T) {
	m, err := connMessage(Conn{Name: "office", Server: server, PSK: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	c := sub(t, m, "office")
	if c.Get("version") != "1" || c.Get("encap") != "yes" {
		t.Errorf("conn: %s", c)
	}
	if got := c.Get("remote_addrs").([]string); len(got) != 1 || got[0] != "203.0.113.9" {
		t.Errorf("remote_addrs %v", got)
	}
	if sub(t, c, "local-1").Get("auth") != "psk" || sub(t, c, "remote-1").Get("id") != "203.0.113.9" {
		t.Errorf("auth: %s", c)
	}
	ch := sub(t, c, "children", "l2tp")
	if ch.Get("mode") != "transport" || ch.Get("start_action") != "trap" || ch.Get("dpd_action") != "trap" || ch.Get("close_action") != "trap" {
		t.Errorf("child: %s", ch)
	}
	for _, k := range []string{"local_ts", "remote_ts"} {
		if got := ch.Get(k).([]string); len(got) != 1 || got[0] != "dynamic[17/1701]" {
			t.Errorf("%s %v", k, got)
		}
	}
	if strings.Contains(m.String(), "secret") {
		t.Error("the key is in the connection")
	}
	p := pskMessage(Conn{Name: "office", Server: server, PSK: "secret"})
	if p.Get("data") != "secret" || p.Get("id") != "rr-psk-office" || p.Get("owners").([]string)[0] != "203.0.113.9" {
		t.Errorf("psk: %s", p)
	}
}

func TestConnMessageCert(t *testing.T) {
	m, err := connMessage(Conn{Name: "office", Server: server, Version: 2, Cert: []byte("CERT"), Key: []byte("KEY"),
		CAs: [][]byte{[]byte("CA")}, RemoteID: "vpn.example.com", Port: 1702})
	if err != nil {
		t.Fatal(err)
	}
	c := sub(t, m, "office")
	l, r := sub(t, c, "local-1"), sub(t, c, "remote-1")
	if c.Get("version") != "2" || l.Get("auth") != "pubkey" || l.Get("certs").([]string)[0] != "CERT" ||
		r.Get("cacerts").([]string)[0] != "CA" || r.Get("id") != "vpn.example.com" {
		t.Errorf("%s", c)
	}
	if got := sub(t, c, "children", "l2tp").Get("local_ts").([]string)[0]; got != "dynamic[17/1702]" {
		t.Errorf("ts %s", got)
	}
}

func TestConnCheck(t *testing.T) {
	for _, c := range []Conn{
		{Name: "bad name", Server: server, PSK: "x"},
		{Name: "a", PSK: "x"},
		{Name: "a", Server: server},
		{Name: "a", Server: server, Cert: []byte("c")},
		{Name: "a", Server: server, PSK: "x", Version: 3},
	} {
		if c.check() == nil {
			t.Errorf("%+v passed", c)
		}
	}
}

func TestKeyType(t *testing.T) {
	for pem, want := range map[string]string{
		"-----BEGIN RSA PRIVATE KEY-----": "rsa", "-----BEGIN EC PRIVATE KEY-----": "ecdsa",
		"-----BEGIN PRIVATE KEY-----": "any", "garbage": "",
	} {
		if got := keyType([]byte(pem)); got != want {
			t.Errorf("%s: %q", pem, got)
		}
	}
}

func TestConf(t *testing.T) {
	mac, linux := Conf("darwin", "/run/x.vici"), Conf("linux", "/run/x.vici")
	if !strings.Contains(mac, "kernel-pfkey kernel-pfroute") || strings.Contains(mac, "kernel-netlink") {
		t.Error(mac)
	}
	if !strings.Contains(linux, "kernel-netlink") || !strings.Contains(linux, "socket = unix:///run/x.vici") ||
		!strings.Contains(linux, "install_routes = no") {
		t.Error(linux)
	}
}

// The failures say what the user can do something about, in the tunnels'
// own phrases.
func TestExplain(t *testing.T) {
	psk := Conn{PSK: "x"}
	cert := Conn{Cert: []byte("c")}
	for _, c := range []struct {
		conn Conn
		log  string
		want string
	}{
		{psk, "received NO_PROPOSAL_CHOSEN error notify", "none of the profile's encryption settings"},
		{psk, "invalid HASH_V1 payload length, decryption failed?", "rejected the shared secret"},
		{psk, "received AUTHENTICATION_FAILED error notify", "rejected the shared secret"},
		{cert, "received AUTHENTICATION_FAILED error notify", "rejected this profile's certificate"},
		{cert, "no trusted RSA public key found for '10.0.0.1'", "couldn't be verified"},
		{psk, "received INVALID_ID_INFORMATION error notify", "selectors"},
		{psk, "giving up after 3 retransmits", "didn't answer"},
		{psk, "something else", "IPsec failed"},
	} {
		err := explain(c.conn, []string{"a", c.log}, errors.New("failed"))
		if got := err.Error(); !strings.Contains(got, c.want) {
			t.Errorf("%q: %q", c.log, got)
		}
		// Only a server that doesn't answer (or an unknown failure) is tried again.
		if retry := strings.Contains(c.log, "retransmit") || c.log == "something else"; Lasting(err) == retry {
			t.Errorf("%q: lasting %v", c.log, Lasting(err))
		}
	}
}

// A charon that prints and never opens its VICI socket: Up gives up, saying
// what it printed, and stops it — without waiting on its own lock (the log
// reader once took the lock Up held, so neither the error nor the stop
// could finish).
func TestCharonThatDoesntStart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a shell script")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "charon")
	script := "#!/bin/sh\ni=0\nwhile [ $i -lt 2000 ]; do echo \"00[DMN] line $i of a lot of output\"; i=$((i+1)); done\necho 'no vici here'\nexec sleep 30\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	w := startWait
	startWait = 500 * time.Millisecond
	t.Cleanup(func() { startWait = w })
	c := &Charon{Bin: bin, Dir: filepath.Join(dir, "run"), GOOS: "linux", Log: slog.New(slog.DiscardHandler)}
	done := make(chan error, 1)
	go func() { done <- c.Up(context.Background(), Conn{Name: "x", Server: server, PSK: "k"}) }()
	select {
	case err := <-done:
		// What it printed last (how far it got is the scheduler's) follows.
		if err == nil || !strings.Contains(err.Error(), "didn't start (no VICI socket): ") {
			t.Fatalf("%v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Up hung")
	}
	stopped := make(chan struct{})
	go func() { c.Down("x"); c.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(15 * time.Second):
		t.Fatal("stopping hung")
	}
}
