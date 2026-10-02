package safety

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/routing"
)

// Live repair: a route RiftRoute installed that the kernel no longer holds —
// another program removed it — is put back by the next apply
// (routing.VerifyRoutes). A program that keeps removing it (a VPN client
// enforcing its own table) would be fought forever, so a route found missing
// liveStrikes times within liveWindow is held: kept as if installed, not put
// back, for liveHold, and reported (HeldRoutes). After that it's tried again.
const (
	liveStrikes = 3
	liveWindow  = 10 * time.Minute
	liveHold    = 30 * time.Minute
	// liveGap: sightings closer than this are one (a burst of applies, or a
	// preview, sees the same removal).
	liveGap = 20 * time.Second
)

type liveRecord struct {
	route     domain.Route
	seen      []time.Time
	heldUntil time.Time
}

type liveRepair struct {
	mu   sync.Mutex
	recs map[string]*liveRecord // by RouteKey
}

// held are the RouteKeys held at now.
func (l *liveRepair) held(now time.Time) map[string]bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]bool{}
	for k, r := range l.recs {
		if now.Before(r.heldUntil) {
			out[k] = true
		}
	}
	return out
}

// note records routes found missing at now, and returns those it starts
// holding.
func (l *liveRepair) note(missing []domain.ManagedRoute, now time.Time) (newlyHeld []domain.Route) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.recs == nil {
		l.recs = map[string]*liveRecord{}
	}
	for k, r := range l.recs { // forget what stopped going missing
		if now.After(r.heldUntil) && (len(r.seen) == 0 || now.Sub(r.seen[len(r.seen)-1]) > liveWindow) {
			delete(l.recs, k)
		}
	}
	for _, m := range missing {
		k := routing.RouteKey(m.Route)
		r := l.recs[k]
		if r == nil {
			r = &liveRecord{route: m.Route}
			l.recs[k] = r
		}
		if n := len(r.seen); n > 0 && now.Sub(r.seen[n-1]) < liveGap {
			continue
		}
		recent := r.seen[:0]
		for _, t := range r.seen {
			if now.Sub(t) <= liveWindow {
				recent = append(recent, t)
			}
		}
		r.seen = append(recent, now)
		if len(r.seen) >= liveStrikes {
			r.heldUntil, r.seen = now.Add(liveHold), nil
			newlyHeld = append(newlyHeld, r.route)
		}
	}
	return newlyHeld
}

// list is what's held at now, by destination.
func (l *liveRepair) list(now time.Time) []domain.HeldRoute {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []domain.HeldRoute
	for _, r := range l.recs {
		if now.Before(r.heldUntil) {
			out = append(out, domain.HeldRoute{Route: r.route, Until: r.heldUntil})
		}
	}
	sort.Slice(out, func(i, j int) bool { return routing.RouteKey(out[i].Route) < routing.RouteKey(out[j].Route) })
	return out
}

// HeldRoutes are the routes another program keeps removing, which the Apply
// Protocol stopped putting back for now.
func (p *Protocol) HeldRoutes() []domain.HeldRoute { return p.live.list(p.clock.Now()) }

// installed is the "actual" side of a reconcile: the owned routes, less those
// desired still wants that the kernel no longer holds — so the plan puts
// them back (routing.VerifyRoutes) — except the held ones. note: count the
// routes found missing toward holding them (an apply, not a preview).
// tunnelsOnly: an apply that vets only its own changes (a tunnel's) puts
// back only tunnel routes; the others it carries over as recorded — with
// auto-apply off after a network move they may be stale, and putting one
// back through the old next hop is a change nobody made.
func (p *Protocol) installed(ctx context.Context, owned, desired []domain.ManagedRoute, note, tunnelsOnly bool) []domain.ManagedRoute {
	now := p.clock.Now()
	var only func(domain.ManagedRoute) bool
	if tunnelsOnly {
		only = routing.IsTunnelRoute
	}
	kept, missing := routing.VerifyRoutes(owned, desired, func(fam domain.Family) ([]domain.Route, error) {
		return p.prov.ListRoutes(ctx, fam)
	}, p.live.held(now), only)
	if note && len(missing) > 0 {
		for _, m := range missing {
			p.log.Info("putting back a route the kernel no longer has", "dst", m.DstCIDR, "gateway", m.Gateway, "iface", m.Iface, "profile", m.ProfileID)
		}
		for _, h := range p.live.note(missing, now) {
			p.log.Warn("another program keeps removing a route; not putting it back for now", "dst", h.DstCIDR, "gateway", h.Gateway, "iface", h.Iface, "for", liveHold)
		}
	}
	return kept
}
