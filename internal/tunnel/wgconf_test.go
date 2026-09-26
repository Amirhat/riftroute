package tunnel

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func key(b byte) string {
	var k [32]byte
	for i := range k {
		k[i] = b
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

// A provider's file, as they hand it out: wg-quick keys RiftRoute doesn't
// run (DNS, hooks, Table) are dropped and reported, AllowedIPs kept for the
// device only.
func TestParseWGProviderFile(t *testing.T) {
	text := strings.Join([]string{
		"# exported by a provider",
		"[Interface]",
		"PrivateKey = " + key(1),
		"Address = 10.64.0.2/32, fd00:64::2/128",
		"DNS = 10.64.0.1",
		"MTU = 1380",
		"PostUp = iptables -A FORWARD -i %i -j ACCEPT",
		"Table = off",
		"",
		"[Peer]",
		"PublicKey = " + key(2),
		"PresharedKey = " + key(3),
		"Endpoint = vpn.example.com:51820",
		"AllowedIPs = 0.0.0.0/0, ::/0",
		"PersistentKeepalive = 25",
	}, "\r\n")
	c, err := ParseWG(text)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Addresses; len(got) != 2 || got[0] != netip.MustParsePrefix("10.64.0.2/32") || got[1] != netip.MustParsePrefix("fd00:64::2/128") {
		t.Errorf("addresses = %v", got)
	}
	if c.MTU != 1380 {
		t.Errorf("MTU = %d", c.MTU)
	}
	if strings.Join(c.Ignored, ",") != "DNS,PostUp,Table" {
		t.Errorf("ignored = %v", c.Ignored)
	}
	if len(c.Peers) != 1 {
		t.Fatalf("%d peers", len(c.Peers))
	}
	p := c.Peers[0]
	if p.Endpoint != (Remote{Host: "vpn.example.com", Port: 51820, Proto: "udp"}) {
		t.Errorf("endpoint = %+v", p.Endpoint)
	}
	if p.PresharedKey == nil || p.PresharedKey[0] != 3 || p.PublicKey[0] != 2 || c.PrivateKey[0] != 1 {
		t.Error("keys not parsed")
	}
	if len(p.AllowedIPs) != 2 || p.Keepalive != 25 {
		t.Errorf("allowed %v keepalive %d", p.AllowedIPs, p.Keepalive)
	}
	if got := c.Servers(); len(got) != 1 || got[0] != "vpn.example.com:51820/udp" {
		t.Errorf("servers = %v", got)
	}
}

func TestParseWGMultiplePeersAndV6Endpoint(t *testing.T) {
	c, err := ParseWG(`[Interface]
PrivateKey=` + key(1) + `
Address=10.0.0.2/24
Address=10.1.0.2/24
[Peer]
PublicKey=` + key(2) + `
Endpoint=[2001:db8::7]:4500
AllowedIPs=10.0.0.0/24
AllowedIPs=10.2.0.0/16
PersistentKeepalive=off
[peer]
PublicKey=` + key(4) + `
Endpoint=198.51.100.9:51820
AllowedIPs=10.1.0.0/24
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Addresses) != 2 || len(c.Peers) != 2 {
		t.Fatalf("addresses %v, %d peers", c.Addresses, len(c.Peers))
	}
	if c.Peers[0].Endpoint.Host != "2001:db8::7" || c.Peers[0].Endpoint.Port != 4500 || len(c.Peers[0].AllowedIPs) != 2 {
		t.Errorf("peer 1 = %+v", c.Peers[0])
	}
	if c.Peers[0].Keepalive != 0 {
		t.Errorf("keepalive off = %d", c.Peers[0].Keepalive)
	}
	if got := c.Remotes(); len(got) != 2 || got[1].Host != "198.51.100.9" {
		t.Errorf("remotes = %v", got)
	}
}

func TestParseWGRefuses(t *testing.T) {
	iface := "[Interface]\nPrivateKey = " + key(1) + "\nAddress = 10.0.0.2/32\n"
	peer := "[Peer]\nPublicKey = " + key(2) + "\nEndpoint = 198.51.100.9:51820\nAllowedIPs = 10.0.0.0/8\n"
	for _, c := range []struct{ name, text, want string }{
		{"no interface", peer, "no [Interface]"},
		{"no private key", "[Interface]\nAddress = 10.0.0.2/32\n" + peer, "no PrivateKey"},
		{"a zero private key", "[Interface]\nPrivateKey = " + key(0) + "\nAddress = 10.0.0.2/32\n" + peer, "all zeros"},
		{"a short key", "[Interface]\nPrivateKey = AAAA\nAddress = 10.0.0.2/32\n" + peer, "not a WireGuard key"},
		{"no address", "[Interface]\nPrivateKey = " + key(1) + "\n" + peer, "no Address"},
		{"no peer", iface, "no [Peer]"},
		{"a peer without a key", iface + "[Peer]\nEndpoint = 198.51.100.9:51820\n", "no PublicKey"},
		{"a peer without an endpoint", iface + "[Peer]\nPublicKey = " + key(2) + "\n", "no Endpoint"},
		{"two interfaces", iface + iface + peer, "second [Interface]"},
		{"an unknown section", iface + "[Proxy]\n" + peer, "unknown section"},
		{"an unknown key", iface + "PostQuantum = on\n" + peer, "isn't a WireGuard setting"},
		{"a peer key in the interface", iface + "Endpoint = 198.51.100.9:1\n" + peer, "isn't a WireGuard setting"},
		{"a key outside a section", "PrivateKey = " + key(1) + "\n" + iface + peer, "outside a section"},
		{"no equals sign", iface + "garbage\n" + peer, "key = value"},
		{"a control character", iface + "MTU = 1420\x0b\n" + peer, "control character"},
		{"a tiny MTU", iface + "MTU = 576\n" + peer, "outside 1280"},
		{"a bad address", "[Interface]\nPrivateKey = " + key(1) + "\nAddress = ten.0.0.2\n" + peer, "not an address"},
		{"a zoned prefix", "[Interface]\nPrivateKey = " + key(1) + "\nAddress = fe80::1%en0/64\n" + peer, "not an address"},
		{"a zoned address", "[Interface]\nPrivateKey = " + key(1) + "\nAddress = fe80::1%en0\n" + peer, "not an address"},
		{"a NUL", iface + "MTU = 14\x0020\n" + peer, "control character"},
		{"an endpoint without a port", iface + "[Peer]\nPublicKey = " + key(2) + "\nEndpoint = vpn.example.com\n", "host:port"},
		{"a bad port", iface + "[Peer]\nPublicKey = " + key(2) + "\nEndpoint = vpn.example.com:99999\n", "valid port"},
		{"an unbracketed v6 endpoint", iface + "[Peer]\nPublicKey = " + key(2) + "\nEndpoint = 2001:db8::7:51820\n", "brackets"},
		{"a loopback endpoint", iface + "[Peer]\nPublicKey = " + key(2) + "\nEndpoint = 127.0.0.1:51820\n", "endpoint 127.0.0.1 is a loopback"},
		{"a host with a space", iface + "[Peer]\nPublicKey = " + key(2) + "\nEndpoint = vpn example.com:51820\n", "valid host"},
		{"a keepalive out of range", iface + "[Peer]\nPublicKey = " + key(2) + "\nEndpoint = 198.51.100.9:1\nPersistentKeepalive = 70000\n", "out of range"},
		{"too large", iface + strings.Repeat("# padding\n", 7000) + peer, "larger than"},
	} {
		_, err := ParseWG(c.text)
		var pe *ProfileError
		if err == nil || !errors.As(err, &pe) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
}

// The errors name the line, and never echo a key.
func TestParseWGErrorsNameTheLineNotTheKey(t *testing.T) {
	secret := key(9)
	_, err := ParseWG("[Interface]\nPrivateKey = " + secret + "\nAddress = 10.0.0.2/32\nMTU = big\n")
	if err == nil || !strings.HasPrefix(err.Error(), "line 4:") {
		t.Fatalf("err = %v", err)
	}
	_, err = ParseWG("[Interface]\nPrivateKey = " + secret[:20] + "\n")
	if err == nil || strings.Contains(err.Error(), secret[:20]) {
		t.Fatalf("err = %v, want no key material", err)
	}
}

func TestParseWGLimits(t *testing.T) {
	iface := "[Interface]\nPrivateKey = " + key(1) + "\nAddress = 10.0.0.2/32\n"
	peer := "[Peer]\nPublicKey = " + key(2) + "\nEndpoint = 198.51.100.9:51820\n"
	if _, err := ParseWG(iface + strings.Repeat(peer, maxWGPeers+1)); err == nil || !strings.Contains(err.Error(), "peers") {
		t.Errorf("too many peers: %v", err)
	}
	many := make([]string, maxWGAllowedIPs+1)
	for i := range many {
		many[i] = netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}).String() + "/24"
	}
	if _, err := ParseWG(iface + peer + "AllowedIPs = " + strings.Join(many, ",") + "\n"); err == nil || !strings.Contains(err.Error(), "allowed IPs") {
		t.Errorf("too many allowed IPs: %v", err)
	}
}

// The device configuration comes only from parsed values: keys as hex,
// endpoints as resolved, and nothing a file line could add.
func TestWGConfigUAPI(t *testing.T) {
	c, err := ParseWG(`[Interface]
PrivateKey = ` + key(1) + `
Address = 10.0.0.2/32
[Peer]
PublicKey = ` + key(2) + `
PresharedKey = ` + key(3) + `
Endpoint = vpn.example.com:51820
AllowedIPs = 10.0.0.0/8, fd00::/8
PersistentKeepalive = 25
[Peer]
PublicKey = ` + key(4) + `
Endpoint = 198.51.100.9:4500
`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.UAPI([]netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:51820")}); err == nil {
		t.Error("UAPI took fewer endpoints than peers")
	}
	got, err := c.UAPI([]netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:51820"), netip.MustParseAddrPort("198.51.100.9:4500")})
	if err != nil {
		t.Fatal(err)
	}
	hex := func(b byte) string {
		return strings.Repeat(string("0123456789abcdef"[b>>4])+string("0123456789abcdef"[b&15]), 32)
	}
	want := "private_key=" + hex(1) + "\nreplace_peers=true\n" +
		"public_key=" + hex(2) + "\npreshared_key=" + hex(3) + "\nendpoint=203.0.113.5:51820\npersistent_keepalive_interval=25\n" +
		"replace_allowed_ips=true\nallowed_ip=10.0.0.0/8\nallowed_ip=fd00::/8\n" +
		"public_key=" + hex(4) + "\nendpoint=198.51.100.9:4500\nreplace_allowed_ips=true\n"
	if got != want {
		t.Errorf("UAPI =\n%s\nwant\n%s", got, want)
	}
}

func TestIsWireGuard(t *testing.T) {
	if !IsWireGuard("# x\n  [Interface]  \nPrivateKey = a\n") {
		t.Error("a wg-quick file wasn't recognized")
	}
	if IsWireGuard("client\ndev tun\nremote vpn.example.com 1194\n") {
		t.Error("an OpenVPN profile was taken for WireGuard")
	}
}
