package splitdns

import (
	"context"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

func TestResolverFile(t *testing.T) {
	got := ResolverFile("10.0.0.53", 0)
	if !strings.Contains(got, "nameserver 10.0.0.53") || !strings.Contains(got, "managed by riftroute") {
		t.Fatalf("resolver file = %q", got)
	}
	if strings.Contains(got, "port") {
		t.Fatalf("port 0 must render no port line: %q", got)
	}
	withPort := ResolverFile("127.0.0.1", 5355)
	if !strings.Contains(withPort, "nameserver 127.0.0.1\nport 5355\n") {
		t.Fatalf("resolver file with port = %q", withPort)
	}
}

// Composed keeps ONE owner of /etc/resolver: user routes + daemon extras are
// always written together, and the shutdown path drops just the extras.
func TestComposedMergesUserAndExtraRoutes(t *testing.T) {
	inner := &FakeManager{}
	extra := []domain.SplitDNSRoute{{Domain: "blumarkets.com", Resolver: "127.0.0.1", Port: 5355}}
	c := NewComposed(inner, func() []domain.SplitDNSRoute { return extra })
	ctx := context.Background()

	user := []domain.SplitDNSRoute{{Domain: "corp.example.com", Resolver: "10.0.0.53"}}
	if err := c.Apply(ctx, user); err != nil {
		t.Fatal(err)
	}
	if len(inner.Applied) != 2 {
		t.Fatalf("want user+extra applied, got %+v", inner.Applied)
	}

	extra = nil // wildcard rules removed → resync drops the proxy entry
	if err := c.Resync(ctx); err != nil {
		t.Fatal(err)
	}
	if len(inner.Applied) != 1 || inner.Applied[0].Domain != "corp.example.com" {
		t.Fatalf("resync should keep only user routes: %+v", inner.Applied)
	}

	extra = []domain.SplitDNSRoute{{Domain: "blucaps.com", Resolver: "127.0.0.1", Port: 5355}}
	_ = c.Resync(ctx)
	if err := c.ApplyUserOnly(ctx); err != nil {
		t.Fatal(err)
	}
	if len(inner.Applied) != 1 {
		t.Fatalf("shutdown path must drop extras: %+v", inner.Applied)
	}
}

func TestFakeManager(t *testing.T) {
	f := &FakeManager{}
	ctx := context.Background()
	routes := []domain.SplitDNSRoute{{Domain: "corp.example.com", Resolver: "10.0.0.53"}}
	if err := f.Apply(ctx, routes); err != nil {
		t.Fatal(err)
	}
	if len(f.Applied) != 1 || f.Applied[0].Domain != "corp.example.com" {
		t.Fatalf("applied = %+v", f.Applied)
	}
	if err := f.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	if f.Applied != nil {
		t.Fatalf("not cleared: %+v", f.Applied)
	}
}
