package core

import (
	"context"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/dns"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider/fake"
)

// The ownership map — not kernel owner tags — must drive the managed count:
// macOS carries no owner tag, so a tag-scan reads 0 there forever (the bug the
// dashboard showed). The store is what the apply protocol reconciles against.
func TestStateManagedCountsFromOwnershipMap(t *testing.T) {
	svc := newSvc(t)
	mr := domain.ManagedRoute{Route: domain.Route{
		DstCIDR: "203.0.113.0/24", Iface: "utun9", Family: domain.FamilyV4,
		Owner: domain.OwnerRiftRoute,
	}, ProfileID: "p1"}
	if err := svc.Store().AddOwned(mr); err != nil {
		t.Fatal(err)
	}
	st, err := svc.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The fake provider never listed this route, mimicking macOS's untagged
	// kernel table — the store must still be believed.
	if st.ManagedRouteCount != 1 {
		t.Fatalf("ManagedRouteCount = %d, want 1 (from ownership map)", st.ManagedRouteCount)
	}
}

// Without a store the provider tag-scan remains the fallback.
func TestStateManagedCountFallsBackToProvider(t *testing.T) {
	prov := fake.New()
	svc := New(prov, nil, "test")
	mr := domain.ManagedRoute{Route: domain.Route{
		DstCIDR: "203.0.113.0/24", Iface: "utun9", Family: domain.FamilyV4,
	}}
	if err := prov.AddRoute(context.Background(), mr); err != nil {
		t.Fatal(err)
	}
	st, err := svc.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.ManagedRouteCount != 1 {
		t.Fatalf("ManagedRouteCount = %d, want 1 (provider fallback)", st.ManagedRouteCount)
	}
}

// A wildcard domain rule must resolve its apex, not literally query "*.x.com"
// (which NXDOMAINs and silently produced zero routes).
func TestResolveDomainsWildcardResolvesApex(t *testing.T) {
	svc := newSvc(t)
	fr := dns.NewFakeResolver()
	fr.Set("example.com", "198.51.100.7")
	svc.SetResolver(dns.NewCache(fr, time.Minute))

	profiles := []domain.Profile{{
		ID: "p1", Name: "wild", Enabled: true, Mode: domain.ModeInclude,
		Rules: []domain.Rule{{Type: domain.RuleDomain, Value: "*.example.com"}},
	}}
	m := svc.resolveDomains(context.Background(), profiles)
	got := m["*.example.com"]
	if len(got) != 1 || got[0] != "198.51.100.7" {
		t.Fatalf("wildcard rule resolved %v, want the apex's [198.51.100.7]", got)
	}
}

// The re-resolver host list must carry apex names so refreshes hit real DNS.
func TestDomainHostsNormalizesWildcards(t *testing.T) {
	svc := newSvc(t)
	p := domain.Profile{
		ID: "p1", Name: "wild", Enabled: true, Mode: domain.ModeExclude,
		Rules: []domain.Rule{
			{Type: domain.RuleDomain, Value: "*.example.com"},
			{Type: domain.RuleDomain, Value: "example.com"}, // dedupes with the wildcard
		},
	}
	if err := svc.Store().UpsertProfile(p); err != nil {
		t.Fatal(err)
	}
	hosts := svc.DomainHosts()
	if len(hosts) != 1 || hosts[0] != "example.com" {
		t.Fatalf("DomainHosts = %v, want [example.com]", hosts)
	}
}
