package safety

import (
	"context"
	"fmt"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider"
)

// Capture takes a full-state snapshot before a mutation (spec §2.1): both
// families' routing tables, policy rules, default routes, and DNS. It is the
// restore point of last resort behind the precomputed inverse.
func Capture(ctx context.Context, prov provider.RouteProvider, id, reason string, now func() domain.Snapshot) (domain.Snapshot, error) {
	v4, err := prov.ListRoutes(ctx, domain.FamilyV4)
	if err != nil {
		return domain.Snapshot{}, fmt.Errorf("snapshot v4 routes: %w", err)
	}
	v6, _ := prov.ListRoutes(ctx, domain.FamilyV6)
	rules4, _ := prov.ListRules(ctx, domain.FamilyV4)
	rules6, _ := prov.ListRules(ctx, domain.FamilyV6)
	dns, _ := prov.DNSConfig(ctx)

	snap := now()
	snap.ID = id
	snap.Reason = reason
	snap.RoutesV4 = v4
	snap.RoutesV6 = v6
	snap.Rules = append(rules4, rules6...)
	snap.DNS = dns
	snap.Defaults = []domain.DefaultRoute{
		defaultFrom(v4, domain.FamilyV4),
		defaultFrom(v6, domain.FamilyV6),
	}
	return snap, nil
}

func defaultFrom(routes []domain.Route, fam domain.Family) domain.DefaultRoute {
	def := "0.0.0.0/0"
	if fam == domain.FamilyV6 {
		def = "::/0"
	}
	for _, r := range routes {
		if r.DstCIDR == def {
			return domain.DefaultRoute{Family: fam, Present: true, Gateway: r.Gateway, Iface: r.Iface, Owner: r.Owner}
		}
	}
	return domain.DefaultRoute{Family: fam, Owner: domain.OwnerUnknown}
}
