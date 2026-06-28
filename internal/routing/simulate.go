package routing

import (
	"net/netip"

	"github.com/Amirhat/riftroute/internal/domain"
)

// Simulate returns RiftRoute's longest-prefix-match decision over a route set —
// the "simulated (desired)" answer shown beside the kernel's real decision in
// route-explain, and the basis for drift detection (spec §7.2). vpnByIface, if
// provided, refines the via-VPN verdict; otherwise it is inferred from owner.
func Simulate(routes []domain.Route, target netip.Addr, vpnByIface map[string]bool) domain.RouteDecision {
	best := -1
	bestBits := -1
	for i, r := range routes {
		pfx, err := netip.ParsePrefix(r.DstCIDR)
		if err != nil {
			continue
		}
		if pfx.Addr().Is4() != target.Is4() {
			continue
		}
		if pfx.Contains(target) && pfx.Bits() > bestBits {
			best = i
			bestBits = pfx.Bits()
		}
	}

	fam := domain.FamilyV4
	if target.Is6() {
		fam = domain.FamilyV6
	}
	dec := domain.RouteDecision{Target: target.String(), Source: "simulated", Family: fam, Reachable: best >= 0}
	if best >= 0 {
		r := routes[best]
		dec.MatchedCIDR = r.DstCIDR
		dec.Gateway = r.Gateway
		dec.Iface = r.Iface
		dec.Owner = r.Owner
		dec.Profile = r.Profile
		if vpnByIface != nil {
			dec.ViaVPN = vpnByIface[r.Iface]
		} else {
			dec.ViaVPN = r.Owner == domain.OwnerVPN
		}
	}
	return dec
}

// Drift reports whether the kernel's real decision diverges from the simulated
// (desired) one — meaning reconciliation is pending (spec §7.2/§7.3).
func Drift(kernel, simulated domain.RouteDecision) bool {
	if kernel.Reachable != simulated.Reachable {
		return true
	}
	if !kernel.Reachable {
		return false
	}
	return kernel.Iface != simulated.Iface || kernel.ViaVPN != simulated.ViaVPN
}
