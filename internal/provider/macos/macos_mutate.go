//go:build darwin

package macos

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// AddRoute installs a managed route via route(8). Idempotent: an already-present
// route is treated as success. Inputs are strictly validated before exec (no
// shell; arg-array only) per spec §12.
func (p *Provider) AddRoute(ctx context.Context, mr domain.ManagedRoute) error {
	args, err := macRouteArgs("add", mr)
	if err != nil {
		return err
	}
	out, err := runCombined(ctx, "route", args...)
	if err != nil {
		if strings.Contains(out, "File exists") {
			return nil // already present → idempotent
		}
		return fmt.Errorf("route add %s: %w: %s", mr.DstCIDR, err, strings.TrimSpace(out))
	}
	return nil
}

// DelRoute removes a managed route via route(8). Idempotent: a missing route is
// treated as success.
func (p *Provider) DelRoute(ctx context.Context, mr domain.ManagedRoute) error {
	args, err := macRouteArgs("delete", mr)
	if err != nil {
		return err
	}
	out, err := runCombined(ctx, "route", args...)
	if err != nil {
		if strings.Contains(out, "not in table") || strings.Contains(out, "No such") {
			return nil // already gone → idempotent
		}
		return fmt.Errorf("route delete %s: %w: %s", mr.DstCIDR, err, strings.TrimSpace(out))
	}
	return nil
}

// FlushOwned removes RiftRoute-owned kernel state on macOS. Routes carry no proto
// tag, so route ownership is DB-tracked and the panic path deletes those
// individually (spec §2.3/§2.5); here we flush our PF policy-routing anchor and
// restore pf.conf — see FlushOwned in pf.go.

// macRouteArgs builds a validated arg-array for `route -n <action> ...`.
func macRouteArgs(action string, mr domain.ManagedRoute) ([]string, error) {
	pfx, err := netip.ParsePrefix(mr.Route.DstCIDR)
	if err != nil {
		return nil, fmt.Errorf("macos: invalid destination CIDR %q", mr.Route.DstCIDR)
	}
	gw, err := netip.ParseAddr(mr.Route.Gateway)
	if err != nil {
		return nil, fmt.Errorf("macos: invalid gateway %q", mr.Route.Gateway)
	}
	if pfx.Addr().Is4() != gw.Is4() {
		return nil, fmt.Errorf("macos: gateway/destination family mismatch")
	}

	args := []string{"-n", action}
	if pfx.Addr().Is6() {
		args = append(args, "-inet6")
	}
	if pfx.Bits() == pfx.Addr().BitLen() {
		// host route: route add -host <ip> <gw>
		args = append(args, "-host", pfx.Addr().String(), gw.String())
	} else {
		args = append(args, "-net", pfx.Masked().String(), gw.String())
	}
	return args, nil
}

func runCombined(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
