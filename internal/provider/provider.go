// Package provider defines the single seam through which all kernel interaction
// flows (spec §4.1). Every read and every mutation of the routing table goes
// through a RouteProvider, so the engine is testable headless against the fake
// implementation and a Windows backend can slot in later.
package provider

import (
	"context"
	"net/netip"

	"github.com/Amirhat/riftroute/internal/domain"
)

// RouteProvider is the per-OS abstraction over the kernel routing table, rules,
// interfaces, and DNS. Implementations: provider/fake (in-memory, for tests and
// dev), provider/macos, provider/linux.
//
// Mutations must be idempotent, use arg-array exec (never a shell string), and
// only ever touch routes RiftRoute owns (spec §2.3, §12).
type RouteProvider interface {
	// --- Reads (safe; never mutate) ---

	// ListRoutes returns the kernel routing table for one family.
	ListRoutes(ctx context.Context, family domain.Family) ([]domain.Route, error)
	// ListRules returns Linux `ip rule` entries; empty on macOS.
	ListRules(ctx context.Context, family domain.Family) ([]domain.PolicyRule, error)
	// LookupRoute asks the kernel where traffic to dst would go.
	LookupRoute(ctx context.Context, dst netip.Addr) (domain.RouteDecision, error)
	// DefaultGateway returns the physical gateway for a family, independent of
	// whether a VPN currently owns the default route (spec §4.4).
	DefaultGateway(ctx context.Context, family domain.Family) (gw netip.Addr, iface string, err error)
	// Interfaces lists interfaces with up/down, addrs, and kind.
	Interfaces(ctx context.Context) ([]domain.Iface, error)
	// DNSConfig returns the resolver configuration in effect.
	DNSConfig(ctx context.Context) (domain.DNSState, error)

	// --- Mutations (idempotent; arg-array exec; owned-only) ---

	AddRoute(ctx context.Context, r domain.ManagedRoute) error
	DelRoute(ctx context.Context, r domain.ManagedRoute) error
	AddRule(ctx context.Context, r domain.ManagedRule) error // Linux Model B
	DelRule(ctx context.Context, r domain.ManagedRule) error
	// FlushOwned removes every RiftRoute-owned route/rule. Powers `panic`.
	FlushOwned(ctx context.Context) error

	// Capabilities reports what this OS supports so the UI can honestly gate
	// features (spec §4.1).
	Capabilities() domain.Capabilities

	// Name is a short provider identifier ("fake" | "macos" | "linux" |
	// "unsupported") surfaced in health/diagnostics.
	Name() string
}
