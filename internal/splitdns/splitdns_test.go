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

func TestResolvectlApplyArgs(t *testing.T) {
	routes := []domain.SplitDNSRoute{
		{Domain: "*.blumarkets.com", Resolver: "127.0.0.1", Port: 5355},
		{Domain: "blumarkets.com", Resolver: "127.0.0.1", Port: 5355}, // apex-dup of the wildcard
		{Domain: "corp.example.com", Resolver: "10.0.0.53"},
	}
	args := resolvectlApplyArgs("lo", routes)
	if len(args) != 2 {
		t.Fatalf("want 2 invocations (dns, domain), got %d: %v", len(args), args)
	}
	dns := strings.Join(args[0], " ")
	// The two 127.0.0.1:5355 entries collapse to one server.
	if dns != "dns lo 127.0.0.1:5355 10.0.0.53" {
		t.Fatalf("dns args = %q", dns)
	}
	dom := strings.Join(args[1], " ")
	// wildcard apex normalized, deduped against the bare apex, all routing-only (~).
	if dom != "domain lo ~blumarkets.com ~corp.example.com" {
		t.Fatalf("domain args = %q", dom)
	}
}

func TestResolvectlServerPortForms(t *testing.T) {
	if got := resolvectlServer("9.9.9.9", 0); got != "9.9.9.9" {
		t.Fatalf("no-port = %q", got)
	}
	if got := resolvectlServer("127.0.0.1", 5355); got != "127.0.0.1:5355" {
		t.Fatalf("v4 port = %q", got)
	}
	if got := resolvectlServer("2001:db8::1", 5355); got != "[2001:db8::1]:5355" {
		t.Fatalf("v6 port = %q", got)
	}
}

func TestComposedPrefersUserOverLearnerForSameDomain(t *testing.T) {
	inner := &FakeManager{}
	// The learner would route example.com to the proxy; the user pinned it to a
	// corp resolver. User must win — else split-horizon DNS breaks silently.
	learner := []domain.SplitDNSRoute{{Domain: "example.com", Resolver: "127.0.0.1", Port: 5355}}
	c := NewComposed(inner, func() []domain.SplitDNSRoute { return learner })
	user := []domain.SplitDNSRoute{{Domain: "example.com", Resolver: "10.0.0.53"}}
	if err := c.Apply(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if len(inner.Applied) != 1 {
		t.Fatalf("collision not deduped: %+v", inner.Applied)
	}
	if inner.Applied[0].Resolver != "10.0.0.53" {
		t.Fatalf("user route must win, got %+v", inner.Applied[0])
	}
}
