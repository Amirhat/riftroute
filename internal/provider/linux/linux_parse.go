// Pure parsers for the Linux backend. Deliberately NOT build-tagged so they can
// be unit-tested on any OS against captured `ip` fixtures (Appendix C). The
// build-tagged glue in linux_read.go shells out to `ip` and feeds the bytes
// here. JSON (`ip -j`) is primary; text parsing is the fallback for old
// iproute2 without `-j` (spec §4.3/§19).
package linux

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/Amirhat/riftroute/internal/domain"
)

// ipRoute mirrors one element of `ip -j route show` / `ip -j route get`.
type ipRoute struct {
	Dst      string `json:"dst"`
	Gateway  string `json:"gateway"`
	Dev      string `json:"dev"`
	Protocol string `json:"protocol"`
	Metric   int    `json:"metric"`
	Table    string `json:"table"`
	Scope    string `json:"scope"`
}

// ipRule mirrors one element of `ip -j rule show`.
type ipRule struct {
	Priority int    `json:"priority"`
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	Table    string `json:"table"`
	FwMark   string `json:"fwmark"`
	Protocol string `json:"protocol"`
	IifName  string `json:"iif"`
	OifName  string `json:"oif"`
}

func normalizeDst(dst string, family domain.Family) string {
	switch {
	case dst == "" || dst == "default":
		if family == domain.FamilyV6 {
			return "::/0"
		}
		return "0.0.0.0/0"
	case !strings.Contains(dst, "/"):
		if family == domain.FamilyV6 {
			return dst + "/128"
		}
		return dst + "/32"
	default:
		return dst
	}
}

// ownerForLinux classifies a route's owner from its proto tag and device. The
// `riftroute` proto is our ownership marker (registered in rt_protos); a default
// via a tunnel device is best-effort VPN; everything else is system.
func ownerForLinux(protocol, dev string) domain.Owner {
	if protocol == "riftroute" {
		return domain.OwnerRiftRoute
	}
	if isTunnel(dev) {
		return domain.OwnerVPN
	}
	return domain.OwnerSystem
}

// parseRoutesJSON parses `ip -j route show` output for one family.
func parseRoutesJSON(data []byte, family domain.Family) ([]domain.Route, error) {
	var raw []ipRoute
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	out := make([]domain.Route, 0, len(raw))
	for _, r := range raw {
		out = append(out, domain.Route{
			DstCIDR: normalizeDst(r.Dst, family),
			Gateway: r.Gateway,
			Iface:   r.Dev,
			Metric:  r.Metric,
			Family:  family,
			Owner:   ownerForLinux(r.Protocol, r.Dev),
			Proto:   r.Protocol,
		})
	}
	return out, nil
}

// parseRulesJSON parses `ip -j rule show` output for one family.
func parseRulesJSON(data []byte, family domain.Family) ([]domain.PolicyRule, error) {
	var raw []ipRule
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	out := make([]domain.PolicyRule, 0, len(raw))
	for _, r := range raw {
		out = append(out, domain.PolicyRule{
			Priority: r.Priority,
			Selector: ruleSelector(r),
			Table:    r.Table,
			Family:   family,
			Proto:    r.Protocol,
		})
	}
	return out, nil
}

func ruleSelector(r ipRule) string {
	var parts []string
	switch {
	case r.Dst != "":
		parts = append(parts, "to "+r.Dst)
	case r.Src != "":
		parts = append(parts, "from "+r.Src)
	default:
		parts = append(parts, "from all")
	}
	if r.FwMark != "" {
		parts = append(parts, "fwmark "+r.FwMark)
	}
	if r.IifName != "" {
		parts = append(parts, "iif "+r.IifName)
	}
	if r.OifName != "" {
		parts = append(parts, "oif "+r.OifName)
	}
	return strings.Join(parts, " ")
}

// parseRouteGetJSON parses `ip -j route get <ip>` into a kernel RouteDecision.
func parseRouteGetJSON(data []byte, target string, family domain.Family) (domain.RouteDecision, error) {
	var raw []ipRoute
	if err := json.Unmarshal(data, &raw); err != nil {
		return domain.RouteDecision{}, err
	}
	dec := domain.RouteDecision{Target: target, Source: "kernel", Family: family}
	if len(raw) == 0 {
		return dec, nil
	}
	r := raw[0]
	dec.Gateway = r.Gateway
	dec.Iface = r.Dev
	dec.Owner = ownerForLinux(r.Protocol, r.Dev)
	dec.Reachable = r.Dev != ""
	dec.ViaVPN = isTunnel(r.Dev)
	return dec, nil
}

// --- text fallbacks (old iproute2 without -j) ---

// parseRoutesText parses `ip route show` text output for one family.
func parseRoutesText(text string, family domain.Family) []domain.Route {
	var out []domain.Route
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		r := domain.Route{Family: family, DstCIDR: normalizeDst(f[0], family)}
		var proto string
		for i := 1; i < len(f)-1; i++ {
			switch f[i] {
			case "via":
				r.Gateway = f[i+1]
			case "dev":
				r.Iface = f[i+1]
			case "proto":
				proto = f[i+1]
			case "metric":
				if n, err := strconv.Atoi(f[i+1]); err == nil {
					r.Metric = n
				}
			}
		}
		r.Proto = proto
		r.Owner = ownerForLinux(proto, r.Iface)
		out = append(out, r)
	}
	return out
}

// parseRouteGetText parses `ip route get <ip>` text output.
func parseRouteGetText(text, target string, family domain.Family) domain.RouteDecision {
	dec := domain.RouteDecision{Target: target, Source: "kernel", Family: family}
	fields := strings.Fields(text)
	for i := 0; i < len(fields)-1; i++ {
		switch fields[i] {
		case "via":
			dec.Gateway = fields[i+1]
		case "dev":
			dec.Iface = fields[i+1]
		}
	}
	dec.Reachable = dec.Iface != ""
	dec.ViaVPN = isTunnel(dec.Iface)
	return dec
}

// classifyIface maps a Linux interface name to a kind and whether it's a tunnel.
func classifyIface(name string) (domain.IfaceKind, bool) {
	switch {
	case name == "lo":
		return domain.IfaceKindLoopback, false
	case strings.HasPrefix(name, "wg"):
		return domain.IfaceKindWG, true
	case strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "tap") ||
		strings.HasPrefix(name, "ppp") || strings.HasPrefix(name, "ipsec") ||
		strings.HasPrefix(name, "utun"):
		return domain.IfaceKindTun, true
	case strings.HasPrefix(name, "br") || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "virbr"):
		return domain.IfaceKindBridge, false
	case strings.HasPrefix(name, "en") || strings.HasPrefix(name, "eth") ||
		strings.HasPrefix(name, "wl") || strings.HasPrefix(name, "wlan"):
		return domain.IfaceKindPhysical, false
	default:
		return domain.IfaceKindOther, false
	}
}

func isTunnel(name string) bool {
	_, t := classifyIface(name)
	return t
}
