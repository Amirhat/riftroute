//go:build darwin

package macos

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

func TestGatewayFromInterfacesSkipsInterfaceWithoutRouter(t *testing.T) {
	old := runCommand
	defer func() { runCommand = old }()
	runCommand = func(_ context.Context, name string, args ...string) (string, error) {
		if name != "ipconfig" {
			t.Fatalf("unexpected command %q", name)
		}
		if args[1] == "en1" {
			return "", errors.New("no router")
		}
		return "192.0.2.1\n", nil
	}

	gw, ifn := (&Provider{}).gatewayFromInterfaces(context.Background(), []string{"en1", "en0"})
	if gw != netip.MustParseAddr("192.0.2.1") || ifn != "en0" {
		t.Fatalf("got gateway %s via %s", gw, ifn)
	}
}

func TestDefaultGatewayPrefersPhysicalDefaultRoute(t *testing.T) {
	old := runCommand
	defer func() { runCommand = old }()
	runCommand = func(_ context.Context, name string, args ...string) (string, error) {
		if name != "route" {
			t.Fatalf("unexpected command %q", name)
		}
		return "gateway: 192.0.2.1\ninterface: en5\n", nil
	}

	gw, ifn, err := (&Provider{}).DefaultGateway(context.Background(), domain.FamilyV4)
	if err != nil {
		t.Fatal(err)
	}
	if gw != netip.MustParseAddr("192.0.2.1") || ifn != "en5" {
		t.Fatalf("got gateway %s via %s", gw, ifn)
	}
}
