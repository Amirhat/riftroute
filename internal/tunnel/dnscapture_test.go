package tunnel

import (
	"fmt"
	"testing"
)

// The DNS options of the last PUSH_REPLY: dhcp-option (old style), and 2.6's
// dns server/search-domains; a server on another port than 53 is left out
// (the system's resolver asks on 53), as are bad addresses and names.
func TestPushedDNS(t *testing.T) {
	lines := []string{
		"2026-10-26 10:00:00 PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.1.1.1'", // an earlier attempt
		"2026-10-26 10:00:05 PUSH: Received control message: 'PUSH_REPLY,route-gateway 10.8.0.1,topology subnet,ping 10," +
			"dhcp-option DNS 10.8.0.1,dhcp-option DNS6 fd00::1,dhcp-option DOMAIN corp.example,dhcp-option DNS 127.0.0.1," +
			"dns server 0 address 10.8.0.2 [fd00::2]:53 10.8.0.3:5353,dns search-domains lab.example bad!name," +
			"ifconfig 10.8.0.6 255.255.255.0,peer-id 0,cipher AES-256-GCM'",
		"2026-10-26 10:00:05 Initialization Sequence Completed",
	}
	servers, search := pushedDNS(lines)
	if fmt.Sprint(servers) != "[10.8.0.1 fd00::1 10.8.0.2 fd00::2]" || fmt.Sprint(search) != "[corp.example lab.example]" {
		t.Fatalf("servers %v, search %v", servers, search)
	}
	if s, d := pushedDNS([]string{"no push here"}); len(s) != 0 || len(d) != 0 {
		t.Fatalf("no reply: %v %v", s, d)
	}
}

// charon-cmd's resolve plugin logs each server it's given, both ways it
// installs them (resolvconf from 5.9.9, a file before), once each.
func TestIKEDNS(t *testing.T) {
	servers := ikeDNS([]string{
		"[CFG] handling INTERNAL_IP4_DNS attribute failed",
		"[IKE] installing DNS server 10.30.0.1 via resolvconf",
		"[IKE] installing DNS server 2001:db8::53 to /tmp/rr-tun-x/office.dns",
		"[IKE] installing DNS server 10.30.0.1 via resolvconf",
		"[IKE] installing DNS server 127.0.0.1 via resolvconf",
		"[IKE] installing DNS server nonsense via resolvconf",
		"[IKE] DNS server 10.30.0.1 already installed, increasing refcount",
	})
	if fmt.Sprint(servers) != "[10.30.0.1 2001:db8::53]" {
		t.Fatalf("servers %v", servers)
	}
	if s := ikeDNS([]string{"[IKE] IKE_SA office[1] established"}); len(s) != 0 {
		t.Fatalf("none given: %v", s)
	}
}
