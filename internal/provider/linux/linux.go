//go:build linux

// Package linux implements RouteProvider on Linux via iproute2 (`ip`) with
// machine-readable (`-j`) output and netlink monitoring (spec §4.3). M0 ships
// the capability surface and structure; real read paths land in M1, mutation
// (Model A + Model B) in M2/M4.
package linux

import (
	"os"
	"path/filepath"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider"
)

// Provider is the Linux RouteProvider. It embeds provider.Base so unimplemented
// methods fail safe with ErrNotImplemented until each is filled in.
type Provider struct {
	provider.Base
}

// New returns a Linux provider. It best-effort registers the "riftroute" proto
// name so `ip route show` reads nicely; correctness never depends on it (we tag
// and match by the numeric value regardless).
func New() *Provider {
	registerProtoName()
	return &Provider{}
}

// registerProtoName maps routeProtoNum → "riftroute" in rt_protos.d so tooling
// prints the friendly name. Best-effort and idempotent: needs root + a writable
// /etc/iproute2 (absent in unprivileged/test namespaces), and any failure is
// ignored because the numeric tag is authoritative.
func registerProtoName() {
	if os.Geteuid() != 0 {
		return
	}
	const dir = "/etc/iproute2/rt_protos.d"
	path := filepath.Join(dir, "riftroute.conf")
	if _, err := os.Stat(path); err == nil {
		return // already registered
	}
	if _, err := os.Stat(dir); err != nil {
		return // no rt_protos.d on this system; skip
	}
	_ = os.WriteFile(path, []byte(routeProtoNum+" "+routeProtoName+"\n"), 0o644)
}

func (p *Provider) Name() string { return "linux" }

// Capabilities reflects Linux's full feature set (spec §4.3): policy routing
// (Model B), fwmark, per-app routing (cgroup+fwmark), and route proto tagging
// for clean ownership.
func (p *Provider) Capabilities() domain.Capabilities {
	return domain.Capabilities{
		Platform:      "linux",
		PolicyRouting: true,
		Fwmark:        true,
		PerAppRouting: true,
		ProtoTag:      true,
		IPv6:          true,
		KillSwitch:    true, // nftables
		IfaceScoping:  false,
	}
}
