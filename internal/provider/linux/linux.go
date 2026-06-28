//go:build linux

// Package linux implements RouteProvider on Linux via iproute2 (`ip`) with
// machine-readable (`-j`) output and netlink monitoring (spec §4.3). M0 ships
// the capability surface and structure; real read paths land in M1, mutation
// (Model A + Model B) in M2/M4.
package linux

import (
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider"
)

// Provider is the Linux RouteProvider. It embeds provider.Base so unimplemented
// methods fail safe with ErrNotImplemented until each is filled in.
type Provider struct {
	provider.Base
}

// New returns a Linux provider.
func New() *Provider { return &Provider{} }

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
