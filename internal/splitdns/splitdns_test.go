package splitdns

import (
	"context"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

func TestResolverFile(t *testing.T) {
	got := ResolverFile("10.0.0.53")
	if !strings.Contains(got, "nameserver 10.0.0.53") || !strings.Contains(got, "managed by riftroute") {
		t.Fatalf("resolver file = %q", got)
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
