package tunnel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A username/password profile whose server pushes redirect-gateway + DNS, as
// real ones do (keys are placeholders).
const pushProfile = `client
dev tun
remote 198.51.100.7 1194 tcp
tun-mtu 1500
tls-client
nobind
user nobody
group nogroup
ping 15
ping-restart 45
persist-tun
persist-key
mute-replay-warnings
verb 3
cipher AES-256-CBC
auth SHA512
pull
auth-user-pass
connect-retry 1
reneg-sec 3600
remote-cert-tls server
<ca>
-----BEGIN CERTIFICATE-----
MIIBfake
-----END CERTIFICATE-----
</ca>
`

// A certificate profile that hard-codes redirect-gateway.
const certProfile = `client
dev tun
proto tcp
remote 203.0.113.9 443
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-128-CBC
auth SHA1
auth-user-pass
redirect-gateway def1
verb 3
<ca>
CA
</ca>
<cert>
CERT
</cert>
<key>
KEY
</key>
`

func TestParseKeepsConnectionDropsRoutingAndDNS(t *testing.T) {
	p, err := Parse(pushProfile)
	if err != nil {
		t.Fatal(err)
	}
	if !p.NeedsAuth {
		t.Error("auth-user-pass profile should need auth")
	}
	if got := p.Servers(); len(got) != 1 || got[0] != "198.51.100.7:1194/tcp" {
		t.Errorf("servers = %v", got)
	}
	if want := []string{"group", "user"}; strings.Join(p.Ignored, ",") != strings.Join(want, ",") {
		t.Errorf("ignored = %v, want %v", p.Ignored, want)
	}
	out := p.Render(RenderOptions{Management: "/run/rr/infra.sock"})
	for _, must := range []string{
		"remote 198.51.100.7 1194 tcp\n", "cipher AES-256-CBC\n", "auth-user-pass\n", "reneg-sec 3600\n",
		"<ca>\n-----BEGIN CERTIFICATE-----", "route-noexec\n", `pull-filter ignore "redirect-gateway"`,
		`pull-filter ignore "dhcp-option"`, "script-security 1\n", "auth-retry none\n",
		"management /run/rr/infra.sock unix\n", "management-hold\n", "management-query-passwords\n",
		"route-nopull\n",
	} {
		if !strings.Contains(out, must) {
			t.Errorf("rendered config lacks %q:\n%s", must, out)
		}
	}
	for _, mustNot := range []string{"user nobody", "group nogroup"} {
		if strings.Contains(out, mustNot) {
			t.Errorf("rendered config still has %q", mustNot)
		}
	}
}

func TestParseCertProfile(t *testing.T) {
	p, err := Parse(certProfile)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Servers(); len(got) != 1 || got[0] != "203.0.113.9:443/tcp" {
		t.Errorf("servers = %v (global proto should apply)", got)
	}
	if strings.Join(p.Ignored, ",") != "redirect-gateway" {
		t.Errorf("ignored = %v", p.Ignored)
	}
	out := p.Render(RenderOptions{Management: "/x.sock"})
	if strings.Contains(out, "redirect-gateway def1") {
		t.Error("redirect-gateway must not reach openvpn")
	}
	for _, blk := range []string{"<ca>\nCA\n</ca>", "<cert>\nCERT\n</cert>", "<key>\nKEY\n</key>"} {
		if !strings.Contains(out, blk) {
			t.Errorf("missing block %q", blk)
		}
	}
}

func TestRenderReplacesRemotesWithPinnedOnes(t *testing.T) {
	p, err := Parse("client\nremote vpn.example.net 443 tcp\nremote backup.example.net\n")
	if err != nil {
		t.Fatal(err)
	}
	out := p.Render(RenderOptions{Remotes: []Remote{{Host: "192.0.2.10", Port: 443, Proto: "tcp"}}, Management: "/m"})
	if !strings.Contains(out, "remote 192.0.2.10 443 tcp\n") || strings.Contains(out, "example.net") {
		t.Fatalf("remotes not replaced:\n%s", out)
	}
	if strings.Count(out, "\nremote ") != 1 {
		t.Fatalf("want exactly the pinned remote:\n%s", out)
	}
}

func TestVerbIsClampedForDiagnosisWithoutPacketDumps(t *testing.T) {
	for in, want := range map[string]string{"": "verb 3\n", "verb 1\n": "verb 3\n", "verb 4\n": "verb 4\n", "verb 11\n": "verb 5\n"} {
		p, err := Parse("client\nremote 192.0.2.1\n" + in)
		if err != nil {
			t.Fatal(err)
		}
		out := p.Render(RenderOptions{Management: "/m"})
		if strings.Count(out, "verb ") != 1 || !strings.Contains(out, want) {
			t.Errorf("%q: rendered\n%s", in, out)
		}
	}
}

func TestParseRefusesDangerousDirectives(t *testing.T) {
	cases := map[string]string{
		"up /tmp/x.sh":                   "runs a script",
		"script-security 2":              "enables scripts",
		"plugin /tmp/evil.so":            "loads a library",
		"engine dynamic":                 "loads a library",
		"log /etc/passwd":                "writes a file",
		"status /etc/sudoers":            "writes a file",
		"config /root/other.conf":        "reads another file",
		"management 127.0.0.1 7505":      "manages the openvpn process",
		"ca /etc/ssl/private/server.key": "inline it",
		"dev tap0":                       "TAP",
		"mode server":                    "unsupported directive",
		"iproute /bin/sh":                "runs a program",
		"setenv opt plugin /tmp/x.so":    "", // dropped whole, never rendered
	}
	for line, want := range cases {
		p, err := Parse("client\nremote 192.0.2.1\n" + line + "\n")
		if want == "" {
			if err != nil {
				t.Errorf("%q: %v", line, err)
			} else if strings.Contains(p.Render(RenderOptions{Management: "/m"}), "plugin") {
				t.Errorf("%q leaked into the config", line)
			}
			continue
		}
		var pe *ProfileError
		if !errors.As(err, &pe) || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want an error containing %q", line, err, want)
		}
	}
}

func TestParseRejectsBrokenInput(t *testing.T) {
	for _, in := range []string{
		"client\n",                    // no remote
		"remote 192.0.2.1\n<ca>\nx\n", // unclosed block
		"remote 192.0.2.1\n<ca>\n</cert>\n</ca>\n", // a closing tag inside a block
		"remote 192.0.2.1\n<ca>\n</ca>\n",          // empty block
		"remote bad_host!\n",                       // bad host
		"remote 192.0.2.1 99999\n",                 // bad port
		"remote 192.0.2.1\nverb \"3\n",             // unterminated quote
		"remote 192.0.2.1\nverb 3\x01\n",           // control character
		"remote 192.0.2.1\ntls-auth [inline] 2\n",  // bad key direction
	} {
		if _, err := Parse(in); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestInlineAuthUserPassBecomesCredentials(t *testing.T) {
	p, err := Parse("client\nremote 192.0.2.1\n<auth-user-pass>\nalice\ns3cret\n</auth-user-pass>\n")
	if err != nil {
		t.Fatal(err)
	}
	if !p.NeedsAuth || p.InlineUser != "alice" || p.InlinePass != "s3cret" {
		t.Fatalf("got %+v", p)
	}
	if strings.Contains(p.Render(RenderOptions{Management: "/m"}), "s3cret") {
		t.Fatal("the password must never be written into the config")
	}
}

func TestQuoteRoundTrips(t *testing.T) {
	for _, s := range []string{"plain", "with space", `quo"te`, `back\slash`, "#hash", "", "/Library/Application Support/x.sock"} {
		toks, err := tokenize("x " + quote(s))
		if err != nil || len(toks) != 2 || toks[1] != s {
			t.Errorf("%q -> %q -> %v %v", s, quote(s), toks, err)
		}
	}
}

func TestInlineFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ca.crt", "CA-PEM\n")
	write("ta.key", "TA-KEY\n")
	write("creds.txt", "bob\nhunter2\n")
	src := "client\nremote 192.0.2.1\nca ca.crt\ntls-auth ta.key 1\nauth-user-pass creds.txt\n<cert>\nINLINE\n</cert>\n"
	out, creds, err := InlineFiles(src, dir, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if creds == nil || creds.Username != "bob" || creds.Password != "hunter2" {
		t.Fatalf("creds = %+v", creds)
	}
	p, err := Parse(out)
	if err != nil {
		t.Fatalf("inlined profile does not parse: %v\n%s", err, out)
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

// openvpn 2.6+ ignores `cipher` in negotiation; a server that only speaks the
// profile's cipher hangs up unless it is offered (as OpenVPN Connect does).
func TestProfileCipherIsOfferedToTheServer(t *testing.T) {
	for _, c := range []struct{ extra, want, not string }{
		{"cipher AES-256-CBC\n", "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC\ndata-ciphers-fallback AES-256-CBC\n", ""},
		{"cipher aes-256-gcm\n", "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\ndata-ciphers-fallback aes-256-gcm\n", ""},
		{"cipher AES-128-CBC\ndata-ciphers AES-256-GCM\n", "data-ciphers AES-256-GCM\ndata-ciphers-fallback AES-128-CBC\n", "CHACHA20"},
		{"cipher AES-256-CBC\ndata-ciphers-fallback AES-128-CBC\n", "AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC\n", "fallback AES-256-CBC"},
		{"cipher BF-CBC\n", "cipher BF-CBC\n", "data-ciphers"},
		{"", "", "data-ciphers"},
	} {
		p, err := Parse("client\nremote 192.0.2.1\n" + c.extra)
		if err != nil {
			t.Fatal(err)
		}
		out := p.Render(RenderOptions{Management: "/m"})
		if !strings.Contains(out, c.want) || (c.not != "" && strings.Contains(out, c.not)) {
			t.Errorf("%q: want %q, not %q, in\n%s", c.extra, c.want, c.not, out)
		}
	}
}

func TestPeerFingerprintValueFormIsKept(t *testing.T) {
	fp := strings.TrimSuffix(strings.Repeat("AB:", 32), ":") // SHA-256
	p, err := Parse("client\nremote 192.0.2.1\npeer-fingerprint " + fp + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Render(RenderOptions{Management: "/m"}), "peer-fingerprint "+fp+"\n") {
		t.Fatal("fingerprint value dropped")
	}
	if _, err := Parse("client\nremote 192.0.2.1\npeer-fingerprint /etc/fp.txt\n"); err == nil {
		t.Fatal("a path must still be refused")
	}
}

// The rendered remote line must read back as exactly remote/host/port/proto,
// whatever the host string holds.
func TestRenderedRemoteCannotInjectWords(t *testing.T) {
	p, err := Parse("client\nremote 192.0.2.1\n")
	if err != nil {
		t.Fatal(err)
	}
	host := "192.0.2.1 53 tcp # rest"
	out := p.Render(RenderOptions{Management: "/m", Remotes: []Remote{{Host: host, Port: 1194, Proto: "udp"}}})
	var n int
	for _, l := range strings.Split(out, "\n") {
		if !strings.HasPrefix(l, "remote ") {
			continue
		}
		n++
		toks, err := tokenize(l)
		if err != nil || len(toks) != 4 || toks[1] != host || toks[2] != "1194" || toks[3] != "udp" {
			t.Errorf("remote line %q reads back as %q (%v)", l, toks, err)
		}
	}
	if n != 1 {
		t.Errorf("want one remote line, got %d:\n%s", n, out)
	}
}

// netip accepts any characters in an IPv6 zone, which Render used to write
// unquoted: `remote "2001:db8::1%x 53 tcp"` became a remote on port 53/tcp.
func TestParseRefusesZonedRemotes(t *testing.T) {
	for _, in := range []string{
		"remote \"2001:db8::1%x 53 tcp #\" 1194 udp\n",
		"remote 2001:db8::1%en0\n",
		"remote fe80::1%utun3\n",
	} {
		_, err := Parse("client\n" + in)
		if err == nil || !strings.Contains(err.Error(), "zone") {
			t.Errorf("%q: got %v, want a zone error", in, err)
		}
	}
}

// A server pinned to the physical gateway at one of these addresses would
// pin a route to loopback, the link, or a multicast group.
func TestParseRefusesUnroutableRemoteAddresses(t *testing.T) {
	for _, host := range []string{
		"127.0.0.1", "127.8.9.10", "::1", "169.254.10.1", "fe80::1", "224.0.0.251",
		"239.1.2.3", "ff02::1", "ff05::2", "0.0.0.0", "::", "::ffff:127.0.0.1", "255.255.255.255",
	} {
		_, err := Parse("client\nremote " + host + " 1194\n")
		if err == nil || !strings.Contains(err.Error(), "can't be a VPN server") {
			t.Errorf("%s: got %v, want it refused", host, err)
		}
	}
	// Host names are resolved (and the addresses filtered) by the daemon.
	for _, host := range []string{"10.0.0.1", "192.168.1.10", "192.0.2.1", "2001:db8::1", "100.64.0.1", "vpn.example.net", "localhost"} {
		if _, err := Parse("client\nremote " + host + " 1194\n"); err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}
}

func TestParseCapsRemotes(t *testing.T) {
	remotes := func(n int) string {
		var b strings.Builder
		for i := range n {
			fmt.Fprintf(&b, "remote 192.0.2.%d 1194\n", i+1)
		}
		return b.String()
	}
	p, err := Parse("client\n" + remotes(maxRemotes))
	if err != nil || len(p.Remotes) != maxRemotes {
		t.Fatalf("%d remotes: %v", maxRemotes, err)
	}
	if _, err := Parse("client\n" + remotes(maxRemotes+1)); err == nil || !strings.Contains(err.Error(), "remote") {
		t.Fatalf("%d remotes: got %v, want refused", maxRemotes+1, err)
	}
	if _, err := Parse("client\nremote 192.0.2.1\n<connection>\nremote 192.0.2.2\n</connection>\n"); err == nil {
		t.Fatal("<connection> blocks stay refused")
	}
}

// route-nopull doesn't stop a server from setting the tunnel's addresses: a
// pushed ifconfig-ipv6 is a connected route, sized by the server. Unless the
// tunnel carries an IPv6 route, the server gets to set no IPv6 at all.
func TestRenderRefusesPushedIPv6UnlessRouted(t *testing.T) {
	p, err := Parse("client\nremote 192.0.2.1\n")
	if err != nil {
		t.Fatal(err)
	}
	filters := []string{"pull-filter ignore \"ifconfig-ipv6\"\n", "pull-filter ignore \"route-ipv6\"\n"}
	out := p.Render(RenderOptions{Management: "/m"})
	for _, f := range filters {
		if !strings.Contains(out, f) {
			t.Errorf("v4-only tunnel lacks %q:\n%s", f, out)
		}
	}
	out = p.Render(RenderOptions{Management: "/m", IPv6: true})
	for _, f := range filters {
		if strings.Contains(out, f) {
			t.Errorf("IPv6 tunnel still has %q", f)
		}
	}
}

func TestRoutesNeedIPv6(t *testing.T) {
	for routes, want := range map[string]bool{
		"":                          false,
		"10.0.0.0/8,192.0.2.7":      false,
		"10.0.0.0/8,2001:db8::/32":  true,
		"2001:db8::7":               true,
		"::ffff:10.0.0.0/104":       false, // v4-mapped: an IPv4 route
		"not-a-route,172.16.0.0/12": false,
	} {
		var rs []string
		if routes != "" {
			rs = strings.Split(routes, ",")
		}
		if got := RoutesNeedIPv6(rs); got != want {
			t.Errorf("RoutesNeedIPv6(%q) = %v, want %v", routes, got, want)
		}
	}
}
