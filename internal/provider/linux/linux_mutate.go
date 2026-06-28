//go:build linux

package linux

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// AddRoute installs a managed route tagged `proto riftroute` so it can be
// enumerated and flushed cleanly (spec §2.3). Idempotent; arg-array exec only.
func (p *Provider) AddRoute(ctx context.Context, mr domain.ManagedRoute) error {
	if err := validateManaged(mr); err != nil {
		return err
	}
	args := []string{"route", "add", mr.Route.DstCIDR, "via", mr.Route.Gateway, "dev", mr.Route.Iface, "proto", "riftroute"}
	if mr.Route.Metric > 0 {
		args = append(args, "metric", fmt.Sprint(mr.Route.Metric))
	}
	out, err := runCombined(ctx, "ip", args...)
	if err != nil {
		if strings.Contains(out, "File exists") {
			return nil
		}
		return fmt.Errorf("ip route add %s: %w: %s", mr.Route.DstCIDR, err, strings.TrimSpace(out))
	}
	return nil
}

// DelRoute removes a managed route (matched by its proto tag).
func (p *Provider) DelRoute(ctx context.Context, mr domain.ManagedRoute) error {
	if _, err := netip.ParsePrefix(mr.Route.DstCIDR); err != nil {
		return fmt.Errorf("linux: invalid destination CIDR %q", mr.Route.DstCIDR)
	}
	out, err := runCombined(ctx, "ip", "route", "del", mr.Route.DstCIDR, "proto", "riftroute")
	if err != nil {
		if strings.Contains(out, "No such process") || strings.Contains(out, "Cannot find") {
			return nil
		}
		return fmt.Errorf("ip route del %s: %w: %s", mr.Route.DstCIDR, err, strings.TrimSpace(out))
	}
	return nil
}

// FlushOwned removes every RiftRoute-owned route in one shot via the proto tag,
// for both families (spec §2.3 owned-enumeration / teardown).
func (p *Provider) FlushOwned(ctx context.Context) error {
	var firstErr error
	for _, fam := range []string{"-4", "-6"} {
		if _, err := runCombined(ctx, "ip", fam, "route", "flush", "proto", "riftroute"); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func validateManaged(mr domain.ManagedRoute) error {
	if _, err := netip.ParsePrefix(mr.Route.DstCIDR); err != nil {
		return fmt.Errorf("linux: invalid destination CIDR %q", mr.Route.DstCIDR)
	}
	if _, err := netip.ParseAddr(mr.Route.Gateway); err != nil {
		return fmt.Errorf("linux: invalid gateway %q", mr.Route.Gateway)
	}
	if strings.TrimSpace(mr.Route.Iface) == "" {
		return fmt.Errorf("linux: empty interface")
	}
	return nil
}

func runCombined(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
