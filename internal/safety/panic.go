package safety

import (
	"context"

	"github.com/Amirhat/riftroute/internal/provider"
)

// Panic removes ALL RiftRoute-managed routes and clears the ownership map,
// restoring the baseline. It is idempotent and must work from any state (spec
// §2.1/§2.5) — it never depends on profiles being consistent.
//
// It deletes each route in the ownership DB (the source of truth on macOS, which
// has no proto tag) and then asks the provider to flush any proto-tagged
// remnants (Linux belt-and-suspenders against DB drift), then clears ownership.
func Panic(ctx context.Context, prov provider.RouteProvider, st Store) error {
	if st != nil {
		if owned, err := st.ListOwned(); err == nil {
			for _, mr := range owned {
				_ = prov.DelRoute(ctx, mr) // best-effort; we must converge to baseline
			}
		}
	}
	_ = prov.FlushOwned(ctx) // Linux proto flush; macOS no-op (DB-driven above)
	if st != nil {
		return st.ClearOwned()
	}
	return nil
}
