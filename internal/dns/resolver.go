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
}

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
	fresh := ok && c.now().Sub(e.at) < c.ttl
	c.mu.Unlock()
	if fresh {
		return e.addrs
	}
	addrs, err := c.resolver.Resolve(ctx, host)
	if err != nil {
		// On failure keep the last good answer (fail-safe — don't drop a route
		// because one lookup timed out).
		return e.addrs
	}
	sortAddrs(addrs)
	c.mu.Lock()
	c.entries[host] = cacheEntry{addrs: addrs, at: c.now()}
	c.mu.Unlock()
	return addrs
}

// Refresh re-resolves every given host and reports whether any answer changed
// (used by the background re-resolver to decide whether to reconcile).
func (c *Cache) Refresh(ctx context.Context, hosts []string) bool {
	changed := false
	for _, h := range hosts {
		addrs, err := c.resolver.Resolve(ctx, h)
		if err != nil {
			continue
		}
		sortAddrs(addrs)
		c.mu.Lock()
		prev := c.entries[h]
		if !sameAddrs(prev.addrs, addrs) {
			changed = true
		}
		c.entries[h] = cacheEntry{addrs: addrs, at: c.now()}
		c.mu.Unlock()
	}
	return changed
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
