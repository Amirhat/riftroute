//go:build darwin

package macos

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

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"github.com/Amirhat/riftroute/internal/domain"
)

// RTAX_* positions within a route message's Addrs slice (sys/socket.h).
const (
	rtaxDst     = 0
	rtaxGateway = 1
	rtaxNetmask = 2
)

// ListRoutes reads the kernel routing table for one family directly from the
// BSD route socket (RIB), avoiding brittle netstat text parsing.
func (p *Provider) ListRoutes(_ context.Context, family domain.Family) ([]domain.Route, error) {
	af := unix.AF_INET
	if family == domain.FamilyV6 {
		af = unix.AF_INET6
	}
	rib, err := route.FetchRIB(af, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, fmt.Errorf("macos: fetch RIB: %w", err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, fmt.Errorf("macos: parse RIB: %w", err)
	}

	ifaceNames := ifaceIndexNames()
	vpnByName := vpnInterfaceSet()

	out := make([]domain.Route, 0, len(msgs))
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok {
			continue
		}
		if rm.Flags&unix.RTF_UP == 0 {
			continue // not an active route
		}
		dst, ok := addrToNetip(rm.Addrs, rtaxDst)
		if !ok {
			continue // not an inet/inet6 destination (e.g. ARP/link entry)
		}
		if (family == domain.FamilyV4) != dst.Is4() {
			continue
		}

		bits := dst.BitLen()
		if rm.Flags&unix.RTF_HOST == 0 {
			bits = maskBits(rm.Addrs, dst.Is4())
		}
		pfx := netip.PrefixFrom(dst, bits)

		gw := ""
		if g, ok := addrToNetip(rm.Addrs, rtaxGateway); ok {
			gw = g.String()
		}

		ifName := ifaceNames[rm.Index]
		owner := domain.OwnerSystem
		if vpnByName[ifName] {
			owner = domain.OwnerVPN
		}

		out = append(out, domain.Route{
			DstCIDR: pfx.Masked().String(),
			Gateway: gw,
			Iface:   ifName,
			Family:  family,
			Owner:   owner,
		})
	}
	return out, nil
}

// ListRules is empty on macOS — there are no policy-routing tables (spec §4.2).
func (p *Provider) ListRules(_ context.Context, _ domain.Family) ([]domain.PolicyRule, error) {
	return []domain.PolicyRule{}, nil
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

// DNSConfig parses `scutil --dns` for the resolvers in effect.
func (p *Provider) DNSConfig(ctx context.Context) (domain.DNSState, error) {
	out, err := run(ctx, "scutil", "--dns")
	if err != nil {
		return domain.DNSState{}, err
	}
	var st domain.DNSState
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "nameserver["):
			if v := afterColon(line); v != "" && !seen[v] {
				seen[v] = true
				st.Servers = append(st.Servers, v)
			}
		case strings.HasPrefix(line, "search domain["):
			if v := afterColon(line); v != "" {
				st.SearchDomains = append(st.SearchDomains, v)
			}
		}
	}
	return st, nil
}

// DefaultGateway returns the physical gateway independent of the VPN default
// route (spec §4.4): it reads the router option off the primary non-tunnel
// interface via ipconfig, falling back to the default route's next hop.
func (p *Provider) DefaultGateway(ctx context.Context, family domain.Family) (netip.Addr, string, error) {
	if family == domain.FamilyV6 {
		// VPN-independent v6 gateway detection lands later; fall back to the
		// kernel default for now.
		gw, ifn, err := p.defaultViaRouteGet(ctx, true)
		return gw, ifn, err
	}
	phys := p.primaryPhysicalIface()
	if phys != "" {
		if out, err := run(ctx, "ipconfig", "getoption", phys, "router"); err == nil {
			if a, perr := netip.ParseAddr(strings.TrimSpace(out)); perr == nil {
				return a, phys, nil
			}
		}
	}
	return p.defaultViaRouteGet(ctx, false)
}

// LookupRoute asks the kernel where traffic to dst goes via `route -n get`.
func (p *Provider) LookupRoute(ctx context.Context, dst netip.Addr) (domain.RouteDecision, error) {
	args := []string{"-n", "get"}
	fam := domain.FamilyV4
	if dst.Is6() {
		args = append(args, "-inet6")
		fam = domain.FamilyV6
	}
	args = append(args, dst.String())
	out, err := run(ctx, "route", args...)
	dec := domain.RouteDecision{Target: dst.String(), Source: "kernel", Family: fam}
	if err != nil {
		// route get exits non-zero when there is no route → unreachable.
		dec.Reachable = false
		return dec, nil
	}
	gw, ifn := parseRouteGet(out)
	dec.Gateway = gw
	dec.Iface = ifn
	dec.Reachable = ifn != ""
	if _, isVPN := classifyIface(ifn); isVPN {
		dec.ViaVPN = true
	}
	return dec, nil
}

// --- helpers ---

func (p *Provider) defaultViaRouteGet(ctx context.Context, v6 bool) (netip.Addr, string, error) {
	args := []string{"-n", "get"}
	if v6 {
		args = append(args, "-inet6")
	}
	args = append(args, "default")
	out, err := run(ctx, "route", args...)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("macos: no default route: %w", err)
	}
	gw, ifn := parseRouteGet(out)
	a, perr := netip.ParseAddr(gw)
	if perr != nil {
		return netip.Addr{}, ifn, fmt.Errorf("macos: default has no gateway address")
	}
	return a, ifn, nil
}

func (p *Provider) primaryPhysicalIface() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		_, isVPN := classifyIface(ifc.Name)
		if isVPN {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				return ifc.Name
			}
		}
	}
	return ""
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C") // stable, parseable output
	out, err := cmd.Output()
	return string(out), err
}

func afterColon(line string) string {
	if i := strings.Index(line, ":"); i >= 0 {
		return strings.TrimSpace(line[i+1:])
	}
	return ""
}

// parseRouteGet extracts the gateway and interface from `route -n get` output.
func parseRouteGet(out string) (gateway, iface string) {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "gateway:"):
			gateway = afterColon(line)
		case strings.HasPrefix(line, "interface:"):
			iface = afterColon(line)
		}
	}
	return gateway, iface
}

// classifyIface maps an interface name to a kind and whether it is a tunnel.
func classifyIface(name string) (domain.IfaceKind, bool) {
	switch {
	case name == "lo0" || strings.HasPrefix(name, "lo"):
		return domain.IfaceKindLoopback, false
	case strings.HasPrefix(name, "utun"):
		return domain.IfaceKindUtun, true
	case strings.HasPrefix(name, "wg"):
		return domain.IfaceKindWG, true
	case strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "tap") || strings.HasPrefix(name, "ipsec") || strings.HasPrefix(name, "ppp"):
		return domain.IfaceKindTun, true
	case strings.HasPrefix(name, "bridge"):
		return domain.IfaceKindBridge, false
	case strings.HasPrefix(name, "en") || strings.HasPrefix(name, "eth"):
		return domain.IfaceKindPhysical, false
	default:
		return domain.IfaceKindOther, false
	}
}

func ifaceIndexNames() map[int]string {
	m := map[int]string{}
	if ifs, err := net.Interfaces(); err == nil {
		for _, ifc := range ifs {
			m[ifc.Index] = ifc.Name
		}
	}
	return m
}

func vpnInterfaceSet() map[string]bool {
	m := map[string]bool{}
	if ifs, err := net.Interfaces(); err == nil {
		for _, ifc := range ifs {
			if _, isVPN := classifyIface(ifc.Name); isVPN {
				m[ifc.Name] = true
			}
		}
	}
	return m
}

// addrToNetip converts the route.Addr at position idx into a netip.Addr.
func addrToNetip(addrs []route.Addr, idx int) (netip.Addr, bool) {
	if idx >= len(addrs) || addrs[idx] == nil {
		return netip.Addr{}, false
	}
	switch a := addrs[idx].(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(a.IP), true
	case *route.Inet6Addr:
		return netip.AddrFrom16(a.IP), true
	default:
		return netip.Addr{}, false
	}
}

// maskBits derives a prefix length from the netmask address in a route message.
func maskBits(addrs []route.Addr, isV4 bool) int {
	if rtaxNetmask >= len(addrs) || addrs[rtaxNetmask] == nil {
		if isV4 {
			return 0
		}
		return 0
	}
	switch a := addrs[rtaxNetmask].(type) {
	case *route.Inet4Addr:
		return countBits(a.IP[:])
	case *route.Inet6Addr:
		return countBits(a.IP[:])
	default:
		if isV4 {
			return 32
		}
		return 128
	}
}

func countBits(mask []byte) int {
	bits := 0
	for _, b := range mask {
		for i := 7; i >= 0; i-- {
			if b&(1<<uint(i)) != 0 {
				bits++
			} else {
				return bits
			}
		}
	}
	return bits
}
