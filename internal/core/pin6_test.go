package core

import (
	"context"
	"net/netip"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/routing"
	"github.com/Amirhat/riftroute/internal/store"
)

// ribProvider lists routes as the macOS RIB does: no owner tag, and a
// link-local gateway's scope embedded in the address (KAME, fe80:4::1), no
// zone — while DefaultGateway reports it as `route get` does (fe80::1%en0).
type ribProvider struct{ *fake.Provider }

func (p ribProvider) ListRoutes(ctx context.Context, fam domain.Family) ([]domain.Route, error) {
	rs, err := p.Provider.ListRoutes(ctx, fam)
	for i, r := range rs {
		rs[i].Owner, rs[i].Proto, rs[i].Profile = domain.OwnerSystem, "", ""
		if a, perr := netip.ParseAddr(r.Gateway); perr == nil && a.Is6() && a.IsLinkLocalUnicast() {
			raw := a.WithZone("").As16()
			raw[3] = 4 // en0's scope
			rs[i].Gateway = netip.AddrFrom16(raw).String()
		}
	}
	return rs, err
}

// RiftRoute's own v6 server pin, via a link-local gateway, is its own: the
// table lists its gateway in another spelling than the one it was recorded
// with. Counted as someone else's route, the next apply withdrew the pin
// (the server "already routed") and the one after re-added it.
func TestAV6PinIsRiftRoutesOwnInTheTable(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	f := fake.New()
	f.SetPhysGateway(domain.FamilyV6, netip.MustParseAddr("fe80::1%en0"), "en0")
	svc := New(ribProvider{f}, st, "test")
	withTunnels(svc, routing.TunnelInput{Name: "infra", Iface: "utun6", V6: true, Routes: []string{"fd00:70::/64"},
		Bypass: []netip.Addr{netip.MustParseAddr("2001:db8::7")}})
	ctx := context.Background()

	pin := func(desired []domain.ManagedRoute) (domain.ManagedRoute, bool) {
		for _, d := range desired {
			if d.DstCIDR == "2001:db8::7/128" {
				return d, true
			}
		}
		return domain.ManagedRoute{}, false
	}
	desired, _, _, err := svc.DesiredTunnelsOnly(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := pin(desired)
	if !ok || p.Gateway != "fe80::1%en0" {
		t.Fatalf("no pin via fe80::1%%en0: %+v", desired)
	}
	for _, d := range desired { // applied: installed and recorded
		if err := f.AddRoute(ctx, d); err != nil {
			t.Fatal(err)
		}
		if err := st.AddOwned(d); err != nil {
			t.Fatal(err)
		}
	}

	owned, _ := st.ListOwned()
	desired, _, _, err = svc.DesiredTunnelsOnly(ctx, owned)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pin(desired); !ok {
		t.Fatalf("the next apply withdraws RiftRoute's own pin: %+v", desired)
	}
	if bl := blockedReasons(svc.TunnelStatuses(ctx)); len(bl) != 0 {
		t.Fatalf("blocked = %v", bl)
	}

	rs, err := svc.Routes(ctx, domain.FamilyV6, domain.OwnerRiftRoute)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 {
		t.Fatalf("the table shows %d of RiftRoute's 2 v6 routes as its own: %+v", len(rs), rs)
	}
}
