//go:build darwin

package macos

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

// fakeRoutes is a provider over a fixed kernel table that records the
// route(8) commands it would run — nothing is exec'd.
func fakeRoutes(kernel []domain.Route, readErr error) (*Provider, *[]string) {
	var ran []string
	p := &Provider{
		listRoutes: func(_ context.Context, fam domain.Family) ([]domain.Route, error) {
			if readErr != nil {
				return nil, readErr
			}
			var out []domain.Route
			for _, r := range kernel {
				if r.Family == fam {
					out = append(out, r)
				}
			}
			return out, nil
		},
		runRoute: func(_ context.Context, args ...string) (string, error) {
			ran = append(ran, strings.Join(args, " "))
			return "", nil
		},
	}
	return p, &ran
}

// route(8) deletes by destination and ignores the gateway, so a managed delete
// runs only while the kernel's route for that destination is still the one
// RiftRoute recorded. Once a tunnel's utun went away (taking its routes), the
// main VPN or the user may route the same destination: withdrawing the tunnel
// must leave that route alone.
func TestManagedDeleteTouchesOnlyOurRoute(t *testing.T) {
	onLink := domain.ManagedRoute{Route: domain.Route{DstCIDR: "192.168.70.0/24", Iface: "utun6", Family: domain.FamilyV4}, ProfileID: "tunnel:infra"}
	pin := domain.ManagedRoute{Route: domain.Route{DstCIDR: "198.51.100.7/32", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4}, ProfileID: "tunnel:infra"}
	v6 := domain.ManagedRoute{Route: domain.Route{DstCIDR: "2001:db8::/32", Gateway: "fe80::1%en0", Iface: "en0", Family: domain.FamilyV6}, ProfileID: "p1"}
	cases := []struct {
		name   string
		mr     domain.ManagedRoute
		kernel []domain.Route
		want   string // the route(8) command run, "" for none
	}{
		{"ours on-link", onLink, []domain.Route{{DstCIDR: "192.168.70.0/24", Iface: "utun6", Family: domain.FamilyV4}}, "-n delete -net 192.168.70.0/24"},
		{"another VPN's now", onLink, []domain.Route{{DstCIDR: "192.168.70.0/24", Gateway: "10.8.0.1", Iface: "utun3", Family: domain.FamilyV4}}, ""},
		{"gone", onLink, nil, ""},
		{"only a clone left", onLink, []domain.Route{{DstCIDR: "192.168.70.0/24", Iface: "utun6", Family: domain.FamilyV4, Cloned: true}}, ""},
		{"our pin", pin, []domain.Route{{DstCIDR: "198.51.100.7/32", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4}}, "-n delete -host 198.51.100.7 192.168.1.1"},
		{"the user's route for our pin's server", pin, []domain.Route{{DstCIDR: "198.51.100.7/32", Gateway: "192.168.1.254", Iface: "en0", Family: domain.FamilyV4}}, ""},
		// The RIB embeds a link-local gateway's scope in the address (KAME).
		{"ours via a link-local gateway", v6, []domain.Route{{DstCIDR: "2001:db8::/32", Gateway: "fe80:4::1", Iface: "en0", Family: domain.FamilyV6}}, "-n delete -inet6 -net 2001:db8::/32 fe80::1%en0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, ran := fakeRoutes(c.kernel, nil)
			if err := p.DelRoute(context.Background(), c.mr); err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(*ran, "; "); got != c.want {
				t.Fatalf("ran %q, want %q", got, c.want)
			}
		})
	}
}

// Unable to read the table, a managed delete refuses rather than delete blind.
// A user's edit of a route RiftRoute doesn't own acts on the route they chose.
func TestDeleteWithoutOwnershipCheck(t *testing.T) {
	mr := domain.ManagedRoute{Route: domain.Route{DstCIDR: "192.168.70.0/24", Iface: "utun6", Family: domain.FamilyV4}, ProfileID: "tunnel:infra"}
	p, ran := fakeRoutes(nil, errors.New("no RIB"))
	if err := p.DelRoute(context.Background(), mr); err == nil || len(*ran) != 0 {
		t.Fatalf("err = %v, ran %v", err, *ran)
	}
	mr.ProfileID = ""
	if err := p.DelRoute(context.Background(), mr); err != nil || len(*ran) != 1 {
		t.Fatalf("external delete: err = %v, ran %v", err, *ran)
	}
}
