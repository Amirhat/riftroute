// Package dns resolves domain-based routing rules (spec §6 v2 / §5.1): a domain
// rule routes the destination's current A/AAAA addresses, and a background
// re-resolver keeps CDNs correct as their IPs rotate. (Split-DNS and DNS-leak
// detection land in M6.)
package dns

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Resolver resolves a hostname to its current A/AAAA addresses.
type Resolver interface {
	Resolve(ctx context.Context, host string) ([]netip.Addr, error)
}

// SystemResolver uses the OS resolver (honoring the system DNS configuration).
type SystemResolver struct{ r net.Resolver }

func (s *SystemResolver) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.r.LookupNetIP(cctx, "ip", host)
}

// Cache wraps a Resolver with a TTL cache so domain rules can be expanded on
// every desired-state build without hammering DNS. The re-resolver refreshes it.
type Cache struct {
	resolver Resolver
	ttl      time.Duration
	now      func() time.Time

	mu      sync.Mutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	addrs []netip.Addr
	at    time.Time
	// failed is when the last lookup failed: for failTTL no lookup of that
	// name is tried again (the last good answer, or none, stands), so a name
	// that can't resolve right now — an internal one behind a tunnel that's
	// down — doesn't cost a resolver timeout on every desired-state build.
	failed time.Time
}

// failTTL is how long a failed lookup stands. The re-resolver (Refresh)
// doesn't wait for it: a name that can't resolve now costs one timeout per
// failTTL at most, not one per change.
const failTTL = 2 * time.Minute

// parallel caps the lookups a Cache runs at once (LookupAll, Refresh).
const parallel = 8

// NewCache builds a TTL cache over a resolver.
func NewCache(r Resolver, ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &Cache{resolver: r, ttl: ttl, now: time.Now, entries: map[string]cacheEntry{}}
}

// Lookup returns cached addresses, resolving (and caching) on a miss/expiry.
func (c *Cache) Lookup(ctx context.Context, host string) []netip.Addr {
	c.mu.Lock()
	e, ok := c.entries[host]
	now := c.now()
	fresh := ok && (now.Sub(e.at) < c.ttl || now.Sub(e.failed) < failTTL)
	c.mu.Unlock()
	if fresh {
		return e.addrs
	}
	addrs, err := c.resolver.Resolve(ctx, host)
	if err != nil {
		// On failure keep the last good answer (fail-safe — don't drop a route
		// because one lookup timed out). The failure is remembered only when
		// it's the name's: a caller that gave up (a closed request) says
		// nothing about it, and must not keep it unresolved for the next.
		c.mu.Lock()
		e = c.entries[host]
		if ctx.Err() == nil {
			e.failed = c.now()
			c.entries[host] = e
		}
		c.mu.Unlock()
		return e.addrs
	}
	sortAddrs(addrs)
	c.mu.Lock()
	c.entries[host] = cacheEntry{addrs: addrs, at: c.now()}
	c.mu.Unlock()
	return addrs
}

// LookupAll is Lookup for each of hosts, a few at a time: a change waits for
// its slowest name, not for the sum of them. done is called as each finishes
// (from any goroutine; nil for none).
func (c *Cache) LookupAll(ctx context.Context, hosts []string, done func()) map[string][]netip.Addr {
	out := make(map[string][]netip.Addr, len(hosts))
	var mu sync.Mutex
	each(hosts, func(h string) {
		addrs := c.Lookup(ctx, h)
		mu.Lock()
		out[h] = addrs
		mu.Unlock()
		if done != nil {
			done()
		}
	})
	return out
}

// Refresh re-resolves every given host, a few at a time, and reports whether
// any answer changed (used by the background re-resolver to decide whether
// to reconcile).
func (c *Cache) Refresh(ctx context.Context, hosts []string) bool {
	var changed atomic.Bool
	each(hosts, func(h string) {
		addrs, err := c.resolver.Resolve(ctx, h)
		if err != nil {
			return
		}
		sortAddrs(addrs)
		c.mu.Lock()
		prev := c.entries[h]
		if !sameAddrs(prev.addrs, addrs) {
			changed.Store(true)
		}
		c.entries[h] = cacheEntry{addrs: addrs, at: c.now()}
		c.mu.Unlock()
	})
	return changed.Load()
}

// each runs fn for every distinct host, at most parallel at a time, and
// returns when all are done.
func each(hosts []string, fn func(string)) {
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	seen := map[string]bool{}
	for _, h := range hosts {
		if seen[h] {
			continue
		}
		seen[h] = true
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			fn(h)
		}()
	}
	wg.Wait()
}

func sortAddrs(a []netip.Addr) {
	sort.Slice(a, func(i, j int) bool { return a[i].Compare(a[j]) < 0 })
}

func sameAddrs(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// FakeResolver is a programmable resolver for tests.
type FakeResolver struct {
	mu sync.Mutex
	m  map[string][]netip.Addr
}

// NewFakeResolver builds an empty fake resolver.
func NewFakeResolver() *FakeResolver { return &FakeResolver{m: map[string][]netip.Addr{}} }

// Set programs a host's answer.
func (f *FakeResolver) Set(host string, addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var as []netip.Addr
	for _, s := range addrs {
		if a, err := netip.ParseAddr(s); err == nil {
			as = append(as, a)
		}
	}
	f.m[host] = as
}

func (f *FakeResolver) Resolve(_ context.Context, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a, ok := f.m[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "not found", Name: host, IsNotFound: true}
}
