package provider

import (
	"context"
	"net/netip"
	"sync"

	"github.com/Amirhat/riftroute/internal/domain"
)

// A route change may need the kernel's table first: on macOS, route(8)
// deletes by destination alone, so a managed delete reads the table and
// deletes only while the route there is still RiftRoute's. Reading the whole
// table for every delete makes a panic — or disabling a big list profile —
// O(N²). A batch of changes (a plan, a rollback, a panic) carries one table
// cache in its context instead: the table is read once per family, and the
// provider keeps the copy current as the batch changes it (RouteAdded,
// RouteDeleted), so a later check in the same batch — a rollback deleting a
// route the plan just added — sees the batch's own changes. What someone
// else changes meanwhile isn't seen until the next batch: a batch is short.
type tableCache struct {
	mu   sync.Mutex
	fams map[domain.Family][]domain.Route
}

type tableCacheKey struct{}

// WithTableCache returns ctx carrying a route-table cache for one batch of
// route changes. A cache ctx already carries is kept.
func WithTableCache(ctx context.Context) context.Context {
	if cacheFrom(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, tableCacheKey{}, &tableCache{fams: map[domain.Family][]domain.Route{}})
}

func cacheFrom(ctx context.Context) *tableCache {
	c, _ := ctx.Value(tableCacheKey{}).(*tableCache)
	return c
}

// CachedRoutes returns fam's table from ctx's cache, reading it with read the
// first time. A failed read isn't cached: the next check reads again. Without
// a cache in ctx it just reads. The result must not be modified.
func CachedRoutes(ctx context.Context, fam domain.Family, read func(context.Context, domain.Family) ([]domain.Route, error)) ([]domain.Route, error) {
	c := cacheFrom(ctx)
	if c == nil {
		return read(ctx, fam)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if rs, ok := c.fams[fam]; ok {
		return rs, nil
	}
	rs, err := read(ctx, fam)
	if err != nil {
		return nil, err
	}
	c.fams[fam] = rs
	return rs, nil
}

// RouteAdded records in ctx's cache a route the provider has just added (not
// one that was already there: the table already shows whose that is).
func RouteAdded(ctx context.Context, r domain.Route) {
	c := cacheFrom(ctx)
	if c == nil {
		return
	}
	dst, err := netip.ParsePrefix(r.DstCIDR)
	c.mu.Lock()
	defer c.mu.Unlock()
	fam := familyOf(dst, r.Family)
	rs, ok := c.fams[fam]
	if !ok {
		return // not read yet: the read will see it
	}
	if err != nil {
		delete(c.fams, fam) // can't be placed: read again
		return
	}
	r.DstCIDR = dst.Masked().String()
	c.fams[fam] = append(rs[:len(rs):len(rs)], r)
}

// RouteDeleted records in ctx's cache that the provider has just deleted the
// route for r's destination (or found it gone).
func RouteDeleted(ctx context.Context, r domain.Route) {
	c := cacheFrom(ctx)
	if c == nil {
		return
	}
	dst, err := netip.ParsePrefix(r.DstCIDR)
	c.mu.Lock()
	defer c.mu.Unlock()
	fam := familyOf(dst, r.Family)
	rs, ok := c.fams[fam]
	if !ok {
		return
	}
	if err != nil {
		delete(c.fams, fam)
		return
	}
	out := make([]domain.Route, 0, len(rs))
	for _, k := range rs {
		if kp, err := netip.ParsePrefix(k.DstCIDR); err == nil && k.Table == r.Table && kp.Masked() == dst.Masked() {
			continue
		}
		out = append(out, k)
	}
	c.fams[fam] = out
}

func familyOf(dst netip.Prefix, fam domain.Family) domain.Family {
	switch {
	case !dst.IsValid():
		return fam
	case dst.Addr().Is6():
		return domain.FamilyV6
	}
	return domain.FamilyV4
}
