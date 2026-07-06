//go:build darwin

// Package macos implements RouteProvider on macOS via route(8) / netstat(8) /
// ipconfig(8) and the BSD route socket (spec §4.2). M0 ships the capability
// surface and structure; real read paths land in M1, mutation in M2.
package macos

import (
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider"
)

// Provider is the macOS RouteProvider. It embeds provider.Base so unimplemented
// methods fail safe with ErrNotImplemented until each is filled in.
type Provider struct {
	provider.Base
}

// New returns a macOS provider.
func New() *Provider { return &Provider{} }

func (p *Provider) Name() string { return "macos" }

// Capabilities reflects macOS's feature set. Policy routing and per-app routing
// are provided natively via PF `route-to` anchors (spec §4.2 / the Darwin
// analogue of Linux Model B): include-mode CIDRs and per-user (uid) selectors
// are steered into the tunnel through our dedicated `riftroute` anchor. Fwmark
// and the route proto tag remain Linux-only kernel primitives — macOS has no
// equivalent — but their JOB (traffic marking + clean rule ownership) is done by
// the PF backend and the anchor's rule labels. Interface scoping (-ifscope) is
// available; ownership of ROUTES stays DB-tracked (no route proto on macOS).
func (p *Provider) Capabilities() domain.Capabilities {
	return domain.Capabilities{
		Platform:      "darwin",
		PolicyRouting: true, // PF route-to anchor
		Fwmark:        false,
		PerAppRouting: true, // PF route-to matching user <uid>
		ProtoTag:      false,
		IPv6:          true,
		KillSwitch:    true, // pf
		IfaceScoping:  true,
		Backend:       "pf",
	}
}
