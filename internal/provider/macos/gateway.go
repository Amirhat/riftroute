package macos

import (
	"net/netip"

	"github.com/Amirhat/riftroute/internal/domain"
)

// pickPhysicalDefault finds the PHYSICAL uplink's gateway in a routing table:
// a main-table v4 default route whose next-hop is a real IP on a non-tunnel
// interface.
//
// This exists because macOS keeps the VPN's default and the physical default
// side by side, e.g.
//
//	default   link#23        UCSg    ipsec0     <- wins, on-link, NO gateway IP
//	default   192.168.88.1   UGScIg  en0        <- the physical gateway
//
// `route -n get default` answers with whichever default currently WINS, so
// while a point-to-point tunnel is up it returns a gateway-less route and the
// physical gateway can't be resolved at all — even though it is sitting right
// there in the table. Exclude-mode profiles need that physical next-hop to
// build bypass routes, so without this the whole desired state fails to
// compute ("no physical gateway for v4") for as long as the VPN is connected.
//
// isVPN reports whether an interface name is a tunnel (injected so this stays
// pure and testable on any platform).
func pickPhysicalDefault(routes []domain.Route, isVPN func(string) bool) (netip.Addr, string, bool) {
	for _, r := range routes {
		if r.Table != "" || r.DstCIDR != "0.0.0.0/0" {
			continue
		}
		if isVPN != nil && isVPN(r.Iface) {
			continue // the tunnel's own default is not a physical path
		}
		a, err := netip.ParseAddr(r.Gateway)
		if err != nil || !a.Is4() {
			continue // on-link (no next-hop) — can't be used as a gateway
		}
		return a, r.Iface, true
	}
	return netip.Addr{}, "", false
}
