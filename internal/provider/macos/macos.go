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

// Capabilities reflects macOS limits (spec §4.2): no policy-routing tables, no
// fwmark / per-app routing, no route proto tag — ownership is DB-tracked and
// interface scoping (-ifscope) is available.
func (p *Provider) Capabilities() domain.Capabilities {
	return domain.Capabilities{
		Platform:      "darwin",
		PolicyRouting: false,
		Fwmark:        false,
		PerAppRouting: false,
		ProtoTag:      false,
		IPv6:          true,
		KillSwitch:    true, // pf
		IfaceScoping:  true,
	}
}
