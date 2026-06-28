package safety

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider"
)

// Violation is a refused or dangerous condition detected before applying (§2.4).
type Violation struct {
	Rule   string `json:"rule"`
	Detail string `json:"detail"`
}

// CheckGuardrails inspects the desired managed routes against current state and
// returns the safety violations that must block an apply (spec §2.4). An empty
// result means it is safe to proceed.
func CheckGuardrails(ctx context.Context, prov provider.RouteProvider, desired []domain.ManagedRoute, physGW netip.Addr) []Violation {
	var vs []Violation

	// 1. Never capture the physical gateway inside a bypass — it can break the
	//    on-link path to the gateway and strand everything.
	if physGW.IsValid() {
		for _, d := range desired {
			if d.Table != "" {
				continue // Model B table routes are isolated; not a main-table capture
			}
			pfx, err := netip.ParsePrefix(d.DstCIDR)
			if err != nil {
				continue
			}
			if pfx.Contains(physGW) {
				vs = append(vs, Violation{
					Rule:   "gateway-capture",
					Detail: fmt.Sprintf("route %s would capture the physical gateway %s", d.DstCIDR, physGW),
				})
			}
		}
	}

	// 2. Every next-hop must be reachable and on-link (not via the VPN), else the
	//    bypass silently fails or blackholes.
	checked := map[string]bool{}
	for _, d := range desired {
		if d.Table != "" {
			continue // a Model B table default intentionally egresses the VPN
		}
		if d.Gateway == "" || checked[d.Gateway] {
			continue
		}
		checked[d.Gateway] = true
		gw, err := netip.ParseAddr(d.Gateway)
		if err != nil {
			vs = append(vs, Violation{Rule: "bad-gateway", Detail: fmt.Sprintf("invalid gateway %q", d.Gateway)})
			continue
		}
		dec, err := prov.LookupRoute(ctx, gw)
		if err != nil {
			continue // can't evaluate; don't block on a read error
		}
		switch {
		case !dec.Reachable:
			vs = append(vs, Violation{Rule: "unreachable-next-hop", Detail: fmt.Sprintf("gateway %s is not reachable", d.Gateway)})
		case dec.ViaVPN:
			vs = append(vs, Violation{Rule: "next-hop-via-vpn", Detail: fmt.Sprintf("gateway %s is not on-link (currently routed via the VPN)", d.Gateway)})
		}
	}

	// 3. SSH-session self-lockout protection: refuse changes that would alter the
	//    route to the peer of an active inbound SSH session (spec §2.4).
	if peer := sshPeer(); peer.IsValid() {
		for _, d := range desired {
			if d.Table != "" {
				continue
			}
			pfx, err := netip.ParsePrefix(d.DstCIDR)
			if err != nil {
				continue
			}
			if pfx.Contains(peer) {
				vs = append(vs, Violation{
					Rule:   "ssh-peer",
					Detail: fmt.Sprintf("change would alter the route to your active SSH peer %s", peer),
				})
			}
		}
	}

	return vs
}

// sshPeer returns the client IP of an active inbound SSH session, if any.
// SSH_CONNECTION = "<clientIP> <clientPort> <serverIP> <serverPort>".
func sshPeer() netip.Addr {
	fields := strings.Fields(os.Getenv("SSH_CONNECTION"))
	if len(fields) < 1 {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(fields[0])
	if err != nil {
		return netip.Addr{}
	}
	return a
}
