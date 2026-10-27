package tunnel

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/Amirhat/riftroute/internal/config"
	"github.com/Amirhat/riftroute/internal/tunneldns"
)

// The DNS a tunnel's server gives, as each engine reports it. RiftRoute
// applies none of it to the system unless the tunnel carries all traffic
// (tunneldns), and even then never lets the engine do it: openvpn keeps its
// pull-filters (it applies nothing without scripts anyway), and charon-cmd's
// resolve plugin, loaded only then, installs it nowhere (ikeConf).

// maxSearchDomains bounds the search domains taken from a server.
const maxSearchDomains = 8

// pushedDNS reads the DNS options in the last PUSH_REPLY openvpn logged
// ("PUSH: Received control message: 'PUSH_REPLY,…'", at verb 3 and up),
// pull-filters notwithstanding: dhcp-option DNS/DNS6/DOMAIN/DOMAIN-SEARCH,
// and OpenVPN 2.6's dns server N address … and dns search-domains.
func pushedDNS(lines []string) (servers []netip.Addr, search []string) {
	reply := ""
	for _, l := range slices.Backward(lines) {
		if i := strings.Index(l, "PUSH_REPLY,"); i >= 0 {
			reply = strings.TrimRight(l[i+len("PUSH_REPLY,"):], "' ")
			break
		}
	}
	addSearch := func(d string) {
		d = strings.TrimSuffix(strings.ToLower(d), ".")
		if config.IsValidDomain(d) && !slices.Contains(search, d) && len(search) < maxSearchDomains {
			search = append(search, d)
		}
	}
	for _, opt := range strings.Split(reply, ",") {
		f := strings.Fields(opt)
		switch {
		case len(f) == 3 && f[0] == "dhcp-option" && (f[1] == "DNS" || f[1] == "DNS6"):
			if a, err := netip.ParseAddr(f[2]); err == nil {
				servers = append(servers, a)
			}
		case len(f) == 3 && f[0] == "dhcp-option" && (f[1] == "DOMAIN" || f[1] == "DOMAIN-SEARCH"):
			addSearch(f[2])
		case len(f) >= 5 && f[0] == "dns" && f[1] == "server" && f[3] == "address":
			for _, s := range f[4:] {
				if a, ok := dnsServerAddr(s); ok {
					servers = append(servers, a)
				}
			}
		case len(f) >= 3 && f[0] == "dns" && f[1] == "search-domains":
			for _, d := range f[2:] {
				addSearch(d)
			}
		}
	}
	return tunneldns.Clean(servers), search
}

// dnsServerAddr reads one address of an OpenVPN `dns server … address`:
// an IP, optionally with a port (1.2.3.4:53, [fd00::1]:53). One on another
// port is left out, since the system's resolver asks on 53.
func dnsServerAddr(s string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr(), ap.Port() == 53
	}
	a, err := netip.ParseAddr(s)
	return a, err == nil
}

// reIKEDNS is the line charon-cmd's resolve plugin logs for each DNS server
// the server gives, whether it then runs resolvconf ("via resolvconf") or
// writes its file ("to <file>"): the same from strongSwan 5.9 to 6.
var reIKEDNS = regexp.MustCompile(`installing DNS server (\S+) (?:via resolvconf|to )`)

// ikeDNS reads the DNS servers in charon-cmd's log.
func ikeDNS(lines []string) []netip.Addr {
	var servers []netip.Addr
	for _, l := range lines {
		if m := reIKEDNS.FindStringSubmatch(l); m != nil {
			if a, err := netip.ParseAddr(m[1]); err == nil {
				servers = append(servers, a)
			}
		}
	}
	return tunneldns.Clean(servers)
}
