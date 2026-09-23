package redact

import (
	"strings"
	"testing"
)

func mustNotContain(t *testing.T, out string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(strings.ToLower(out), strings.ToLower(s)) {
			t.Errorf("leaked %q in:\n%s", s, out)
		}
	}
}

func mustContain(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("want %q in:\n%s", w, out)
		}
	}
}

// Lines shaped exactly like a real affected machine's daemon log and
// diagnostics: nothing identifying may survive, the structure must.
func TestRedactsRealDaemonLog(t *testing.T) {
	r := New()
	r.Add(Profile, "J", "Work VPN")
	r.Add(Domain, "*.jaryan.app")
	in := `time=2026-08-13T11:22:33.123+03:30 level=WARN msg="reconcile failed" err="profile \"Work VPN\": no physical gateway for v4 (cannot resolve gateway: auto)"
time=2026-08-13T11:22:34.001+03:30 level=INFO msg="wildcard subdomain learned" rule=*.jaryan.app name=api.jaryan.app addrs=2
resolver /etc/resolver/jaryan.app -> nameserver 127.0.0.1 port 54452
default via 192.168.88.1 dev en0; 7 routes via 192.168.50.254
dns 10.255.255.2, 127.0.0.1, 1.1.1.1, 9.9.9.9
nym-vpnd 812 root 21u IPv4 TCP 192.168.88.23:51514->76.76.21.21:443 (ESTABLISHED)`
	out := r.String(in)
	mustNotContain(t, out, "Work VPN", "jaryan", "192.168.88.1", "192.168.50.254", "192.168.88.23", "76.76.21.21", "10.255.255.2", "+03:30", "api.")
	mustContain(t, out,
		"2026-08-13T07:52:33.123Z",        // timezone gone, instant kept
		`profile \"<profile-1>\"`,         // name → placeholder
		"rule=*.<domain-1>",               // wildcard keeps its shape
		"name=<sub-1>.<domain-1>",         // subdomain hidden, apex relation kept
		"/etc/resolver/<domain-1>",        // same domain, same placeholder
		"127.0.0.1", "1.1.1.1", "9.9.9.9", // loopback / public resolvers kept
		"default via <ip4-lan-1> dev en0", // routes stay readable
		"<ip4-1>:443",                     // public endpoint, port kept
		"no physical gateway for v4",      // the actual error is untouched
	)
}

func TestKnownTokensMatchWholeWordsOnly(t *testing.T) {
	r := New()
	r.Add(Profile, "Work")
	r.Add(User, "amir")
	out := r.String(`profile Work enabled; Network OK; homework; user=amir; amirhat is the repo owner`)
	mustContain(t, out, "profile <profile-1> enabled", "Network OK", "homework", "user=<user-1>", "amirhat")
	// Glued by punctuation is still a match — a leak costs more than
	// over-redaction does.
	out = r.String(`/tmp/claude-501/-Users-amir-Golang host amir-mbp.lan dir /Users/amir_old mail amir.h@x`)
	mustNotContain(t, out, "-amir-", "amir-mbp", "amir_old", "amir.h")
	// One-character names are too short to identify anyone — and too short to
	// replace safely.
	r2 := New()
	r2.Add(Profile, "J")
	if out := r2.String(`J JSON jq`); out != `J JSON jq` {
		t.Fatalf("1-char token must not be replaced everywhere, got %q", out)
	}
}

func TestPlaceholdersAreStableAcrossCalls(t *testing.T) {
	r := New()
	a := r.String("gw 192.168.1.1 dns 192.168.1.53")
	b := r.String("again 192.168.1.53 and 192.168.1.1")
	mustContain(t, a, "gw <ip4-lan-1> dns <ip4-lan-2>")
	mustContain(t, b, "again <ip4-lan-2> and <ip4-lan-1>")
	if r.Count() != 2 {
		t.Fatalf("Count = %d, want 2", r.Count())
	}
}

func TestAddressClasses(t *testing.T) {
	r := New()
	out := r.String(strings.Join([]string{
		"lan 10.8.0.2/24", "public 5.6.7.8", "cgnat 100.72.1.9", "ll 169.254.3.4",
		"keep 0.0.0.0/0 127.0.0.1 255.255.255.0 255.255.255.255 224.0.0.251 198.51.100.7",
		"v6 2a01:4f8:c0c:1::2/64", "ula fd00:abcd::1", "ll6 fe80::1c2:3%en0", "keep6 ::1 :: 2001:db8::5 2606:4700:4700::1111",
	}, "\n"))
	mustNotContain(t, out, "10.8.0.2", "5.6.7.8", "100.72.1.9", "169.254.3.4", "2a01:4f8", "fd00:abcd", "fe80::1c2", "192.168.9.9")
	mustContain(t, out,
		"lan <ip4-lan-1>/24", "public <ip4-1>", "cgnat <ip4-cgnat-1>", "ll <ip4-ll-1>",
		"keep 0.0.0.0/0 127.0.0.1 255.255.255.0 255.255.255.255 224.0.0.251 198.51.100.7",
		"v6 <ip6-1>/64", "ula <ip6-lan-1>", "ll6 <ip6-ll-1>", "keep6 ::1 :: 2001:db8::5 2606:4700:4700::1111",
	)
	// An IPv4-mapped IPv6 address is the IPv4 address: same placeholder.
	r2 := New()
	if out := r2.String("a 192.168.9.9 b ::ffff:192.168.9.9"); out != "a <ip4-lan-1> b <ip4-lan-1>" {
		t.Fatalf("mapped address: %q", out)
	}
}

// Things that merely LOOK like addresses or domains must survive: times,
// versions, file names, reverse-DNS identifiers, our own endpoints.
func TestLeavesNonSensitiveLookalikesAlone(t *testing.T) {
	r := New()
	in := "at 06:03:47 v0.2.4-dev go1.25.0 /var/log/riftroute/riftrouted.err.log com.riftroute.daemon.plist " +
		"RiftRoute.app riftroute.db api.github.com riftroute.tellnew.tech pf.conf 1.2.3 e.g. i/o"
	if out := r.String(in); out != in {
		t.Fatalf("non-sensitive text changed:\n in: %s\nout: %s", in, out)
	}
}

// A domain glued to other letters by "-" is a different domain: redacted as
// a whole, not presented as a subdomain of the known one.
func TestKnownDomainNotConfusedWithLookalike(t *testing.T) {
	r := New()
	r.Add(Domain, "jaryan.app")
	out := r.String("a www.jaryan.app b my-jaryan.app")
	mustNotContain(t, out, "jaryan")
	mustContain(t, out, "a <sub-1>.<domain-1> b")
}

func TestUnknownDomainsURLsMACsAndHomePaths(t *testing.T) {
	r := New()
	r.Add(Host, "Amirs-MacBook-Pro")
	out := r.String("lookup secret-corp.example.org failed; list https://lists.example.net/iran.txt?token=abc; " +
		"mac aa:bb:cc:dd:ee:ff; open /Users/amir/Library/x and /home/amir/.config; host amirs-macbook-pro.local")
	mustNotContain(t, out, "secret-corp", "example.org", "lists.example.net", "token=abc", "aa:bb:cc", "/Users/amir", "/home/amir", "macbook")
	mustContain(t, out, "lookup <domain-1> failed", "list <url-1>", "mac <mac-1>", "/Users/<user>/Library/x", "/home/<user>/.config", "host <host-1>.local")
}

// Names as the logger prints them: %q-escaped, and escaped again when the
// error is itself a quoted slog attribute. Persian names carry ZWNJ, which
// %q writes as \u200c.
func TestKnownNamesMatchInEscapedForms(t *testing.T) {
	r := New()
	r.Add(Profile, "سایت\u200cهای ایرانی", `Mom's "Bank"`)
	in := `drift — profile "سایت\u200cهای ایرانی": no tunnel
err="profile \"Mom's \\\"Bank\\\"\": no physical gateway" profile="سایت\u200cهای ایرانی"`
	out := r.String(in)
	mustNotContain(t, out, "سایت", "Mom", "Bank")
	if strings.Count(out, "<profile-1>") != 2 || strings.Count(out, "<profile-2>") != 1 {
		t.Fatalf("each name must map to ONE placeholder in every spelling:\n%s", out)
	}
}

// Nobody registered these names (daemon down, or a profile deleted since the
// log line was written) — they are caught by where they sit.
func TestUnregisteredNamesMaskedByPosition(t *testing.T) {
	r := New()
	in := `a: profile "Old Bank": gone
b: err="profile \"Old Bank\": no gateway"
c: msg="restore: could not remove profile" profile=Tehran-Office list="iran banks"
d: per-app include rule "alice" has no tunnel
e: network event type=up iface=nordlynx; iface=en0; iface=utun4
f: rule=*.example.org keeps its shape; the profile set is empty; nft list table inet riftroute`
	out := r.String(in)
	mustNotContain(t, out, "Old Bank", "Tehran", "iran banks", "alice", "nordlynx")
	mustContain(t, out,
		`a: profile "<profile-1>": gone`,
		`b: err="profile \"<profile-1>\": no gateway"`, // same name, same placeholder
		`profile=<profile-2> list="<list-1>"`,
		`rule "<rule-1>"`,
		`iface=<iface-1>; iface=en0; iface=utun4`,
		`rule=*.<domain-1>`,
		"the profile set is empty", "nft list table inet riftroute",
	)
}

func TestIPv6WithSurroundingPunctuation(t *testing.T) {
	r := New()
	out := r.String("add host 2a01:4f8::1: gateway x; route 2a01:4f8:c0c:1::2: file exists; peer 2a01:4f8::77. dst:2a01:4f8::99 tcp 2a01:4f8::2.443")
	mustNotContain(t, out, "2a01")
	mustContain(t, out, "add host <ip6-1>: gateway", "route <ip6-2>: file exists", "peer <ip6-3>.", "dst:<ip6-4>", "tcp <ip6-5>.443")
}

func TestDomainEdgeCases(t *testing.T) {
	r := New()
	out := r.String("bank.xn--mgba3a4f16a shop.xn--p1ai evil.md bun.sh foo.new bücher.de 例子.公司 README.md-ish")
	mustNotContain(t, out, "bank.", "shop.", "evil", "bun", "foo.new", "bücher", "bü", "例子")
	out = r.String("mail jdoe@example.com; socks5://amir:hunter2@proxy.example.net:1080 ; lists.example.net/iran.txt?token=abc end")
	mustNotContain(t, out, "jdoe", "hunter2", "iran.txt", "token=abc")
	mustContain(t, out, "mail <email-1>;", "<url-1>", "<domain-", "/… end")
}

func TestIPv4EdgeCases(t *testing.T) {
	r := New()
	out := r.String("gw_192.168.1.1 10.0.0.1_ext x192.168.1.5 pad 192.168.001.001 short 10.8/16 192.168.88/24 not 1.2.3.4.5 v1.2.3")
	mustNotContain(t, out, "192.168", "10.0.0.1", "10.8/16")
	mustContain(t, out, "gw_<ip4-lan-1>", "<ip4-lan-2>_ext", "x<ip4-lan-3>", "pad <ip4-lan-1>", "short <ip4-lan-", "/16", "not 1.2.3.4.5", "v1.2.3")
}

func TestMACInsideIPv6AndEscapedHomePaths(t *testing.T) {
	r := New()
	out := r.String(`fd12:3456:aa:bb:cc:dd:ee:ff and fd00::aa:bb:cc:dd:ee:ff mac aa:bb:cc:dd:ee:ff json "\/Users\/bob\/x"`)
	mustNotContain(t, out, "fd12", "fd00", "3456", "bob")
	mustContain(t, out, "<ip6-lan-1> and <ip6-lan-2> mac <mac-1>", `\/Users\/<user>\/x`)
}

func TestBrandedIfacesAreNotGeneric(t *testing.T) {
	for _, n := range []string{"ham0", "zt3jnkd3", "nordlynx", "wg-mullvad"} {
		if GenericIface(n) {
			t.Errorf("%s names a product", n)
		}
	}
}
