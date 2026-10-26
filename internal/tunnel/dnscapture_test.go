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

// charon-cmd's resolve plugin writes a resolv.conf of its own.
func TestResolvConfDNS(t *testing.T) {
	servers, search := resolvConfDNS("nameserver 10.30.0.1   # by strongSwan\nnameserver 2001:db8::53   # by strongSwan\n# comment\nsearch Corp.Example.\nnameserver nonsense\n")
	if fmt.Sprint(servers) != "[10.30.0.1 2001:db8::53]" || fmt.Sprint(search) != "[corp.example]" {
		t.Fatalf("servers %v, search %v", servers, search)
	}
}
