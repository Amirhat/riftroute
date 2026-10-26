package tunnel

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/Amirhat/riftroute/internal/config"
	"github.com/Amirhat/riftroute/internal/tunneldns"
)

// The DNS a tunnel's server gives, as each engine reports it. RiftRoute
// applies none of it to the system unless the tunnel carries all traffic
// (tunneldns), and even then never lets the engine do it: openvpn keeps its
// pull-filters (it applies nothing without scripts anyway), and charon-cmd's
// resolve plugin only writes a file of the session's own.

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
// an IP, optionally with a port (1.2.3.4:53, [fd00::1]:53) — the port is
// dropped, since the system's resolver asks on 53.
func dnsServerAddr(s string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr(), ap.Port() == 53
	}
	a, err := netip.ParseAddr(s)
	return a, err == nil
}

// resolvConfDNS reads the file charon-cmd's resolve plugin writes:
// "nameserver <addr>" lines (with its "# by strongSwan" comments) and an
// optional "search" line.
func resolvConfDNS(text string) (servers []netip.Addr, search []string) {
	for _, line := range strings.Split(text, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		switch {
		case len(f) == 2 && f[0] == "nameserver":
			if a, err := netip.ParseAddr(f[1]); err == nil {
				servers = append(servers, a)
			}
		case len(f) >= 2 && (f[0] == "search" || f[0] == "domain"):
			for _, d := range f[1:] {
				d = strings.TrimSuffix(strings.ToLower(d), ".")
				if config.IsValidDomain(d) && !slices.Contains(search, d) && len(search) < maxSearchDomains {
					search = append(search, d)
				}
			}
		}
	}
	return tunneldns.Clean(servers), search
}
