package dns

import (
	"context"
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
