//go:build linux

package linux

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// ListRoutes reads the routing table for one family via `ip -j route show`,
// falling back to text parsing on old iproute2 without `-j`.
func (p *Provider) ListRoutes(ctx context.Context, family domain.Family) ([]domain.Route, error) {
	fam := famFlag(family)
	if out, err := run(ctx, "ip", "-j", fam, "route", "show"); err == nil {
		if routes, perr := parseRoutesJSON([]byte(out), family); perr == nil {
			return routes, nil
		}
	}
	out, err := run(ctx, "ip", fam, "route", "show")
	if err != nil {
		return nil, fmt.Errorf("linux: ip route show: %w", err)
	}
	return parseRoutesText(out, family), nil
}

// ListRules reads policy rules for one family via `ip -j rule show`.
func (p *Provider) ListRules(ctx context.Context, family domain.Family) ([]domain.PolicyRule, error) {
	out, err := run(ctx, "ip", "-j", famFlag(family), "rule", "show")
	if err != nil {
		return []domain.PolicyRule{}, nil // best-effort; rules are Model B
	}
	rules, perr := parseRulesJSON([]byte(out), family)
	if perr != nil {
		return []domain.PolicyRule{}, nil
	}
	return rules, nil
}

// LookupRoute asks the kernel where traffic to dst goes via `ip route get`.
func (p *Provider) LookupRoute(ctx context.Context, dst netip.Addr) (domain.RouteDecision, error) {
	family := domain.FamilyV4
	if dst.Is6() {
		family = domain.FamilyV6
	}
	if out, err := run(ctx, "ip", "-j", "route", "get", dst.String()); err == nil {
		if dec, perr := parseRouteGetJSON([]byte(out), dst.String(), family); perr == nil {
			return dec, nil
		}
	}
	out, err := run(ctx, "ip", "route", "get", dst.String())
	if err != nil {
		return domain.RouteDecision{Target: dst.String(), Source: "kernel", Family: family, Reachable: false}, nil
	}
	return parseRouteGetText(out, dst.String(), family), nil
}

// Interfaces enumerates interfaces via the stdlib and classifies each by name.
func (p *Provider) Interfaces(_ context.Context) ([]domain.Iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]domain.Iface, 0, len(ifs))
	for _, ifc := range ifs {
		kind, isVPN := classifyIface(ifc.Name)
		var addrs []string
		if as, err := ifc.Addrs(); err == nil {
			for _, a := range as {
				addrs = append(addrs, a.String())
			}
		}
		out = append(out, domain.Iface{
			Name:  ifc.Name,
			Up:    ifc.Flags&net.FlagUp != 0,
			Kind:  kind,
			Addrs: addrs,
			MTU:   ifc.MTU,
			IsVPN: isVPN,
		})
	}
	return out, nil
}

// DNSConfig reads resolvers from /etc/resolv.conf (systemd-resolved/NM both
// surface effective resolvers there; resolvectl integration lands later).
func (p *Provider) DNSConfig(_ context.Context) (domain.DNSState, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return domain.DNSState{}, err
	}
	defer f.Close()
	var st domain.DNSState
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			st.Servers = append(st.Servers, fields[1])
		case "search", "domain":
			st.SearchDomains = append(st.SearchDomains, fields[1:]...)
		}
	}
	return st, nil
}

// DefaultGateway returns the physical gateway: the default route's next hop on a
// non-tunnel device (so it stays correct while a VPN owns the default — spec
// §4.4), falling back to any default gateway.
func (p *Provider) DefaultGateway(ctx context.Context, family domain.Family) (netip.Addr, string, error) {
	routes, err := p.ListRoutes(ctx, family)
	if err != nil {
		return netip.Addr{}, "", err
	}
	def := defaultCIDR(family)
	var fallbackGW, fallbackIf string
	for _, r := range routes {
		if r.DstCIDR != def || r.Gateway == "" {
			continue
		}
		if !isTunnel(r.Iface) {
			a, perr := netip.ParseAddr(r.Gateway)
			if perr == nil {
				return a, r.Iface, nil
			}
		}
		if fallbackGW == "" {
			fallbackGW, fallbackIf = r.Gateway, r.Iface
		}
	}
	if fallbackGW != "" {
		if a, perr := netip.ParseAddr(fallbackGW); perr == nil {
			return a, fallbackIf, nil
		}
	}
	return netip.Addr{}, "", fmt.Errorf("linux: no default gateway for %s", family)
}

// --- helpers ---

func run(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	return string(out), err
}

func famFlag(family domain.Family) string {
	if family == domain.FamilyV6 {
		return "-6"
	}
	return "-4"
}

func defaultCIDR(family domain.Family) string {
	if family == domain.FamilyV6 {
		return "::/0"
	}
	return "0.0.0.0/0"
}
