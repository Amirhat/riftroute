package provider

import (
	"context"
	"errors"
	"net/netip"

	"github.com/Amirhat/riftroute/internal/domain"
)

// ErrNotImplemented is returned by provider methods not yet implemented for the
// current platform. It lets platform backends be built incrementally while the
// project always compiles (spec §8/§14).
var ErrNotImplemented = errors.New("riftroute: not implemented for this platform")

// Base provides not-implemented defaults for every RouteProvider method. Embed
// it in a platform backend and override methods as they come online; on its own
// it serves as the "unsupported platform" provider (e.g. a future Windows host)
// so the daemon always has a working, fail-safe RouteProvider.
type Base struct{}

func (Base) ListRoutes(context.Context, domain.Family) ([]domain.Route, error) {
	return nil, ErrNotImplemented
}
func (Base) ListRules(context.Context, domain.Family) ([]domain.PolicyRule, error) {
	return nil, ErrNotImplemented
}
func (Base) LookupRoute(context.Context, netip.Addr) (domain.RouteDecision, error) {
	return domain.RouteDecision{}, ErrNotImplemented
}
func (Base) DefaultGateway(context.Context, domain.Family) (netip.Addr, string, error) {
	return netip.Addr{}, "", ErrNotImplemented
}
func (Base) Interfaces(context.Context) ([]domain.Iface, error) { return nil, ErrNotImplemented }
func (Base) DNSConfig(context.Context) (domain.DNSState, error) {
	return domain.DNSState{}, ErrNotImplemented
}
func (Base) AddRoute(context.Context, domain.ManagedRoute) error { return ErrNotImplemented }
func (Base) DelRoute(context.Context, domain.ManagedRoute) error { return ErrNotImplemented }
func (Base) AddRule(context.Context, domain.ManagedRule) error   { return ErrNotImplemented }
func (Base) DelRule(context.Context, domain.ManagedRule) error   { return ErrNotImplemented }
func (Base) FlushOwned(context.Context) error                    { return ErrNotImplemented }

func (Base) Capabilities() domain.Capabilities {
	return domain.Capabilities{Platform: "unsupported"}
}
func (Base) Name() string { return "unsupported" }

// NewUnsupported returns a fail-safe provider for platforms without a real
// backend. All mutations refuse; all reads report not-implemented.
func NewUnsupported() RouteProvider { return Base{} }
