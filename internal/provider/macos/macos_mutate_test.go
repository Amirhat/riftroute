//go:build darwin

package macos

import (
	"reflect"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

func TestMacRouteArgsChangeManagedHostRoute(t *testing.T) {
	mr := domain.ManagedRoute{Route: domain.Route{
		DstCIDR: "203.0.113.7/32",
		Gateway: "192.0.2.1",
		Iface:   "en0",
		Family:  domain.FamilyV4,
	}, ProfileID: "manual-bypass"}

	got, err := macRouteArgs("change", mr)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-n", "change", "-host", "203.0.113.7", "192.0.2.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("change args = %v, want %v", got, want)
	}
}
