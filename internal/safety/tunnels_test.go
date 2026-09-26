package safety_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

// ApplyBuilt hands the build what RiftRoute owns under the apply lock, and a
// build error aborts before anything is touched.
func TestApplyBuiltBuildsFromTheOwnedSet(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.mustApply(t, desired("9.9.9.0/24"))

	var saw []domain.ManagedRoute
	res, err := h.p.ApplyBuilt(ctx, func(owned []domain.ManagedRoute) ([]domain.ManagedRoute, []domain.ManagedRule, error) {
		saw = owned
		return append(owned, desired("8.8.8.0/24")...), nil, nil
	}, opts(false))
	if err != nil || res.Status != domain.TxPending {
		t.Fatalf("apply: %s %v", res.Status, err)
	}
	if len(saw) != 1 || saw[0].DstCIDR != "9.9.9.0/24" {
		t.Fatalf("build saw %+v, want the owned 9.9.9.0/24", saw)
	}
	if h.prov.CountManaged() != 2 {
		t.Fatalf("managed = %d, want 2", h.prov.CountManaged())
	}

	boom := errors.New("boom")
	res, err = h.p.ApplyBuilt(ctx, func([]domain.ManagedRoute) ([]domain.ManagedRoute, []domain.ManagedRule, error) {
		return nil, nil, boom
	}, opts(false))
	if !errors.Is(err, boom) || res.Status != domain.TxFailed || h.prov.CountManaged() != 2 {
		t.Fatalf("a failed build must change nothing: %s %v, managed %d", res.Status, err, h.prov.CountManaged())
	}
}

// mustApply runs a non-interactive apply that must go through.
func (h *harness) mustApply(t *testing.T, d []domain.ManagedRoute) {
	t.Helper()
	res, err := h.p.Apply(context.Background(), d, nil, opts(false))
	if err != nil || res.Status != domain.TxPending {
		t.Fatalf("apply: %s %v %v", res.Status, err, res.Violations)
	}
}
