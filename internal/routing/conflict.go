package routing

import (
	"fmt"
	"net/netip"

	"github.com/Amirhat/riftroute/internal/domain"
)

// DetectConflicts finds managed routes that overlap but send traffic to
// DIFFERENT next hops — the cases that surprise users because longest-prefix
// match silently picks one (spec §7.8). Overlaps that share a next hop are
// harmless redundancy and are not reported.
func DetectConflicts(routes []domain.ManagedRoute) []domain.Conflict {
	type entry struct {
		pfx netip.Prefix
		r   domain.ManagedRoute
	}
	var es []entry
	for _, r := range routes {
		if p, err := netip.ParsePrefix(r.Route.DstCIDR); err == nil {
			es = append(es, entry{p.Masked(), r})
		}
	}

	var out []domain.Conflict
	for i := 0; i < len(es); i++ {
		for j := i + 1; j < len(es); j++ {
			a, b := es[i], es[j]
			if a.pfx.Addr().Is4() != b.pfx.Addr().Is4() {
				continue
			}
			if !a.pfx.Overlaps(b.pfx) {
				continue
			}
			if a.r.Route.Gateway == b.r.Route.Gateway && a.r.Route.Iface == b.r.Route.Iface {
				continue // same next hop → harmless
			}
			kind := "overlap"
			detail := "overlapping destinations with different next hops"
			switch {
			case a.pfx.Bits() == b.pfx.Bits():
				kind = "duplicate"
				detail = "same destination routed two different ways"
			case a.pfx.Bits() != b.pfx.Bits():
				kind = "shadowed"
				detail = "the more-specific route wins (longest-prefix match); the broader one is partly shadowed"
			}
			out = append(out, domain.Conflict{
				Kind:   kind,
				A:      label(a.r),
				B:      label(b.r),
				Detail: detail,
			})
		}
	}
	return out
}

func label(r domain.ManagedRoute) string {
	prof := r.ProfileID
	if prof == "" {
		prof = r.Route.Profile
	}
	return fmt.Sprintf("%s via %s dev %s (%s)", r.Route.DstCIDR, r.Route.Gateway, r.Route.Iface, prof)
}
