package safety

import (
	"context"
	"fmt"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider"
	"github.com/Amirhat/riftroute/internal/routing"
)

// Panic removes ALL RiftRoute-managed routes and clears the ownership map,
// restoring the baseline. It is idempotent and must work from any state (spec
// §2.1/§2.5) — it never depends on profiles being consistent.
//
// It deletes each route in the ownership DB (the source of truth on macOS, which
// has no proto tag) and then asks the provider to flush any proto-tagged
// remnants (Linux belt-and-suspenders against DB drift), then clears ownership.
// The deletes share one read of the route table (provider.WithTableCache).
//
// A route whose delete failed — or was skipped, the table unreadable — and
// that is still in the kernel after the flush keeps its record: forgotten,
// nothing would ever remove it. Panic then reports how many are left, and a
// retry (another panic, the next apply) removes them.
func Panic(ctx context.Context, prov provider.RouteProvider, st Store) error {
	ctx = provider.WithTableCache(ctx)
	var owned, failed []domain.ManagedRoute
	var firstErr error
	if st != nil {
		var err error
		if owned, err = st.ListOwned(); err == nil {
			for _, mr := range owned {
				if derr := prov.DelRoute(ctx, mr); derr != nil { // best-effort; we must converge to baseline
					failed = append(failed, mr)
					if firstErr == nil {
						firstErr = derr
					}
				}
			}
		}
	}
	// Provider-level sweep: Linux flushes proto-tagged routes/rules; macOS empties
	// the PF route-to anchor and restores pf.conf (routes stay DB-driven above).
	_ = prov.FlushOwned(ctx)
	if st == nil {
		return nil
	}
	if failed = stillInstalled(ctx, prov, failed); len(failed) == 0 {
		return st.ClearOwned()
	}
	keep := map[string]bool{}
	for _, mr := range failed {
		keep[routing.RouteKey(mr.Route)] = true
	}
	for _, mr := range owned {
		if !keep[routing.RouteKey(mr.Route)] {
			_ = st.DelOwned(mr)
		}
	}
	return fmt.Errorf("%d managed route(s) could not be removed and stay recorded for a retry: %w", len(failed), firstErr)
}

// stillInstalled returns the routes of rs the kernel still holds after the
// flush (Linux's flush takes proto-tagged routes whose delete failed) — all
// of them when the table can't be read.
func stillInstalled(ctx context.Context, prov provider.RouteProvider, rs []domain.ManagedRoute) []domain.ManagedRoute {
	if len(rs) == 0 {
		return nil
	}
	var kernel []domain.Route
	for _, fam := range []domain.Family{domain.FamilyV4, domain.FamilyV6} {
		k, err := prov.ListRoutes(ctx, fam)
		if err != nil {
			return rs
		}
		kernel = append(kernel, k...)
	}
	in := routing.IndexInstalled(kernel)
	var out []domain.ManagedRoute
	for _, r := range rs {
		if in.Has(r.Route) {
			out = append(out, r)
		}
	}
	return out
}
