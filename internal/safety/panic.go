package safety

import (
	"context"

	"github.com/Amirhat/riftroute/internal/provider"
)

// Panic removes ALL RiftRoute-managed routes and clears the ownership map,
// restoring the baseline. It is idempotent and must work from any state (spec
// §2.1/§2.5) — it never depends on profiles being consistent.
func Panic(ctx context.Context, prov provider.RouteProvider, st Store) error {
	if err := prov.FlushOwned(ctx); err != nil {
		return err
	}
	if st != nil {
		return st.ClearOwned()
	}
	return nil
}
