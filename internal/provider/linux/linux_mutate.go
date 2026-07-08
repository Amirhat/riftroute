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
	"github.com/Amirhat/riftroute/internal/routing"
)

// AddRoute installs a managed route tagged `proto riftroute` so it can be
// enumerated and flushed cleanly (spec §2.3). Supports a dedicated table (Model
// B) and an on-link tunnel default (no gateway). Idempotent; arg-array only.
func (p *Provider) AddRoute(ctx context.Context, mr domain.ManagedRoute) error {
	if err := validateManaged(mr); err != nil {
		return err
	}
	args := []string{"route", "add", mr.Route.DstCIDR}
	if mr.Route.Gateway != "" {
		args = append(args, "via", mr.Route.Gateway)
	}
	args = append(args, "dev", mr.Route.Iface, "proto", protoArg(mr.Route.Proto))
	if mr.Route.Metric > 0 {
		args = append(args, "metric", fmt.Sprint(mr.Route.Metric))
	}
	if mr.Route.Table != "" {
		args = append(args, "table", mr.Route.Table)
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

// DelRoute removes a route, matched by its proto tag + table. Managed routes
// carry proto riftroute; EXTERNAL routes (user edits from the routing table)
// carry whatever proto the kernel reported (dhcp/static/kernel/…) — matching
// on OUR tag there would simply fail to find them.
func (p *Provider) DelRoute(ctx context.Context, mr domain.ManagedRoute) error {
	if _, err := netip.ParsePrefix(mr.Route.DstCIDR); err != nil {
		return fmt.Errorf("linux: invalid destination CIDR %q", mr.Route.DstCIDR)
	}
	args := []string{"route", "del", mr.Route.DstCIDR, "proto", protoArg(mr.Route.Proto)}
	if mr.Route.Table != "" {
		args = append(args, "table", mr.Route.Table)
	}
	out, err := runCombined(ctx, "ip", args...)
	if err != nil {
		if strings.Contains(out, "No such process") || strings.Contains(out, "Cannot find") {
			return nil
		}
		return fmt.Errorf("ip route del %s: %w: %s", mr.Route.DstCIDR, err, strings.TrimSpace(out))
	}
	return nil
}

// protoArg maps a route's proto to the `ip route` argument: RiftRoute's own
// tag (also the default and the "riftroute" alias), or the kernel-reported
// proto of an external route, charset-vetted for the exec arg-array.
func protoArg(proto string) string {
	if proto == "" || proto == routeProtoName {
		return routeProtoNum
	}
	for _, r := range proto {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return routeProtoNum // unexpected value → fail closed onto our own tag
		}
	}
	return proto
}

// AddRule installs a policy rule (Model B), proto-tagged for ownership. Falls
// back to no proto tag on older iproute2 that lacks rule `protocol` support.
func (p *Provider) AddRule(ctx context.Context, mr domain.ManagedRule) error {
	base := []string{"rule", "add"}
	base = append(base, strings.Fields(mr.Selector)...)
	base = append(base, "lookup", mr.Table, "priority", fmt.Sprint(mr.Priority))

	out, err := runCombined(ctx, "ip", append(append([]string{}, base...), "protocol", routeProtoNum)...)
	if err != nil {
		if strings.Contains(out, "File exists") {
			return nil
		}
		if strings.Contains(out, "protocol") { // old iproute2: retry without the tag
			if out2, err2 := runCombined(ctx, "ip", base...); err2 != nil {
				if strings.Contains(out2, "File exists") {
					return nil
				}
				return fmt.Errorf("ip rule add: %w: %s", err2, strings.TrimSpace(out2))
			}
			return nil
		}
		return fmt.Errorf("ip rule add: %w: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// DelRule removes a policy rule (matched by selector + table + priority).
func (p *Provider) DelRule(ctx context.Context, mr domain.ManagedRule) error {
	args := []string{"rule", "del"}
	args = append(args, strings.Fields(mr.Selector)...)
	args = append(args, "lookup", mr.Table, "priority", fmt.Sprint(mr.Priority))
	out, err := runCombined(ctx, "ip", args...)
	if err != nil {
		if strings.Contains(out, "No such") || strings.Contains(out, "Cannot find") {
			return nil
		}
		return fmt.Errorf("ip rule del: %w: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// FlushOwned removes every RiftRoute-owned route and rule in one shot (spec §2.3
// teardown): proto-tagged routes in the main and Model B tables (both families),
// the Model B table itself, and proto-tagged rules.
func (p *Provider) FlushOwned(ctx context.Context) error {
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, fam := range []string{"-4", "-6"} {
		// Route flushes are best-effort teardown: a not-yet-created Model B table,
		// a disabled address family (some hosts have IPv6 off), or "nothing to
		// flush" must not fail the operation. The DB-driven Panic path deletes the
		// actually-owned routes individually; this is the belt-and-suspenders sweep.
		_, _ = runCombined(ctx, "ip", fam, "route", "flush", "proto", routeProtoNum)
		_, _ = runCombined(ctx, "ip", fam, "route", "flush", "proto", routeProtoNum, "table", routing.ModelBTable)
		// Delete proto-tagged rules enumerated from `ip -j rule show`.
		if out, e := runCombined(ctx, "ip", "-j", fam, "rule", "show"); e == nil {
			if rules, perr := parseRulesJSON([]byte(out), famOf(fam)); perr == nil {
				for _, r := range rules {
					if r.Proto != routeProtoName { // normalized by parseRulesJSON
						continue
					}
					mr := domain.ManagedRule{PolicyRule: r}
					note(p.DelRule(ctx, mr))
				}
			}
		}
	}
	return firstErr
}

func famOf(flag string) domain.Family {
	if flag == "-6" {
		return domain.FamilyV6
	}
	return domain.FamilyV4
}

func validateManaged(mr domain.ManagedRoute) error {
	if _, err := netip.ParsePrefix(mr.Route.DstCIDR); err != nil {
		return fmt.Errorf("linux: invalid destination CIDR %q", mr.Route.DstCIDR)
	}
	if mr.Route.Gateway != "" {
		if _, err := netip.ParseAddr(mr.Route.Gateway); err != nil {
			return fmt.Errorf("linux: invalid gateway %q", mr.Route.Gateway)
		}
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
