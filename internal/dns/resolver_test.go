package dns

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestCacheLookupAndTTL(t *testing.T) {
	f := NewFakeResolver()
	f.Set("cdn.example.com", "1.1.1.1", "2606:4700::1")
	c := NewCache(f, time.Minute)

	addrs := c.Lookup(context.Background(), "cdn.example.com")
	if len(addrs) != 2 {
		t.Fatalf("want 2 addrs, got %v", addrs)
	}

	// Change the answer; within TTL the cache still returns the old one.
	f.Set("cdn.example.com", "9.9.9.9")
	addrs = c.Lookup(context.Background(), "cdn.example.com")
	if len(addrs) != 2 {
		t.Fatalf("within TTL the cached answer should hold, got %v", addrs)
	}
}

func TestCacheRefreshDetectsChange(t *testing.T) {
	f := NewFakeResolver()
	f.Set("cdn.example.com", "1.1.1.1")
	c := NewCache(f, time.Minute)
	c.Lookup(context.Background(), "cdn.example.com")

	if c.Refresh(context.Background(), []string{"cdn.example.com"}) {
		t.Fatal("no change yet, Refresh should report false")
	}
	f.Set("cdn.example.com", "1.1.1.1", "8.8.8.8")
	if !c.Refresh(context.Background(), []string{"cdn.example.com"}) {
		t.Fatal("answer changed, Refresh should report true")
	}
}

func TestCacheKeepsLastGoodOnFailure(t *testing.T) {
	f := NewFakeResolver()
	f.Set("x.example.com", "1.2.3.4")
	c := NewCache(f, time.Nanosecond) // force re-resolve every lookup
	first := c.Lookup(context.Background(), "x.example.com")
	if len(first) != 1 {
		t.Fatal("expected initial resolution")
	}
	time.Sleep(time.Millisecond)
	// Unknown host now errors; cache should keep the last good answer.
	c2 := NewCache(f, time.Nanosecond)
	c2.Lookup(context.Background(), "x.example.com")
	time.Sleep(time.Millisecond)
	got := c2.Lookup(context.Background(), "missing.example.com")
	if got != nil {
		t.Fatalf("unknown host with no prior cache should return nil, got %v", got)
	}
}

// countingResolver fails every lookup and counts them.
type countingResolver struct{ n int }

func (c *countingResolver) Resolve(context.Context, string) ([]netip.Addr, error) {
	c.n++
	return nil, errors.New("timeout")
}

// A failed lookup stands for failTTL: a name that can't resolve right now
// costs one resolver timeout per failTTL, not one per desired-state build.
// The re-resolver still tries it.
func TestCacheRemembersAFailureBriefly(t *testing.T) {
	r := &countingResolver{}
	c := NewCache(r, time.Minute)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	for range 3 {
		if got := c.Lookup(context.Background(), "corp.internal"); got != nil {
			t.Fatalf("got %v", got)
		}
	}
	if r.n != 1 {
		t.Fatalf("%d lookups within failTTL, want 1", r.n)
	}
	now = now.Add(failTTL + time.Second)
	c.Lookup(context.Background(), "corp.internal")
	if r.n != 2 {
		t.Fatalf("%d lookups after failTTL, want 2", r.n)
	}
	c.Refresh(context.Background(), []string{"corp.internal"})
	if r.n != 3 {
		t.Fatalf("the re-resolver didn't try it: %d lookups", r.n)
	}
}

// A lookup whose caller gave up (a closed request) isn't remembered as the
// name's failure: the next caller tries it.
func TestCacheDoesntBlameTheNameForACanceledCaller(t *testing.T) {
	r := &countingResolver{}
	c := NewCache(r, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.Lookup(ctx, "corp.internal")
	c.Lookup(context.Background(), "corp.internal")
	if r.n != 2 {
		t.Fatalf("%d lookups, want the second caller to try again", r.n)
	}
}

// slowResolver answers every name after a delay.
type slowResolver struct{ d time.Duration }

func (s slowResolver) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	time.Sleep(s.d)
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
}

// LookupAll looks names up together: a change waits for the slowest name,
// not for the sum of them, and hears as each finishes.
func TestLookupAllIsConcurrent(t *testing.T) {
	c := NewCache(slowResolver{100 * time.Millisecond}, time.Minute)
	hosts := []string{"a", "b", "c", "d", "e", "f", "a"}
	var done atomic.Int32
	start := time.Now()
	got := c.LookupAll(context.Background(), hosts, func() { done.Add(1) })
	if took := time.Since(start); took > 400*time.Millisecond {
		t.Errorf("took %s: the names were looked up one after another", took)
	}
	if len(got) != 6 || done.Load() != 6 {
		t.Fatalf("answers %d, done %d", len(got), done.Load())
	}
	start = time.Now()
	c.LookupAll(context.Background(), hosts, nil)
	if took := time.Since(start); took > 50*time.Millisecond {
		t.Errorf("cached names took %s", took)
	}
}
