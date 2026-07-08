// Package splitdns implements per-domain resolver selection (split-DNS, spec
// §6/§7.6): queries for a configured domain go to a chosen resolver instead of
// the system default. macOS uses scoped resolvers (/etc/resolver/<domain>);
// Linux uses systemd-resolved per-domain routing (resolvectl). The macOS
// resolver-file generator is pure and unit-tested; real application writes
// system files and is Linux/macOS + root only — the agent never applies it on a
// live host.
package splitdns

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

const resolverDir = "/etc/resolver" // macOS scoped-resolver directory

// Manager applies/clears split-DNS routes.
type Manager interface {
	Apply(ctx context.Context, routes []domain.SplitDNSRoute) error
	Clear(ctx context.Context) error
	Backend() string
}

// New returns the per-OS manager.
func New() Manager {
	switch runtime.GOOS {
	case "darwin":
		return &macResolverManager{}
	case "linux":
		return &resolvectlManager{}
	default:
		return &macResolverManager{unsupported: true}
	}
}

// ResolverFile renders a macOS /etc/resolver/<domain> file pointing the domain at
// the given resolver (pure; unit-tested). port 0 means the default 53.
func ResolverFile(resolver string, port int) string {
	if port > 0 {
		return fmt.Sprintf("# managed by riftroute\nnameserver %s\nport %d\n", resolver, port)
	}
	return fmt.Sprintf("# managed by riftroute\nnameserver %s\n", resolver)
}

type macResolverManager struct{ unsupported bool }

func (m *macResolverManager) Backend() string {
	if m.unsupported {
		return "unsupported"
	}
	return "resolver-files"
}

func (m *macResolverManager) Apply(_ context.Context, routes []domain.SplitDNSRoute) error {
	if m.unsupported {
		return fmt.Errorf("split-DNS unsupported on %s", runtime.GOOS)
	}
	if err := os.MkdirAll(resolverDir, 0o755); err != nil {
		return err
	}
	if err := m.Clear(context.Background()); err != nil {
		return err
	}
	for _, r := range routes {
		// macOS resolver files match the domain and all its subdomains, so a
		// wildcard normalizes to its apex (a literal "*.example.com" filename
		// would never match anything).
		path := filepath.Join(resolverDir, domain.DomainRuleHost(r.Domain))
		if err := os.WriteFile(path, []byte(ResolverFile(r.Resolver, r.Port)), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return nil
}

func (m *macResolverManager) Clear(_ context.Context) error {
	if m.unsupported {
		return nil
	}
	entries, err := os.ReadDir(resolverDir)
	if err != nil {
		return nil // dir absent → nothing to clear
	}
	for _, e := range entries {
		path := filepath.Join(resolverDir, e.Name())
		b, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(b), "managed by riftroute") {
			_ = os.Remove(path)
		}
	}
	return nil
}

// resolvectlManager implements split-DNS on systemd-resolved. Its model is
// per-LINK, not per-server: a link carries a set of DNS servers and a set of
// routing domains, and queries for any routed domain go to that link's server
// set (spec §6). RiftRoute uses ONE dedicated link ("lo", which always exists)
// so its config is isolated and reverted atomically: the wildcard learner's
// apexes route to the loopback proxy, and any user split-DNS resolvers join
// the same link's server set. The command construction is pure/unit-tested;
// real application is Linux + root only.
type resolvectlManager struct {
	link string // "" → the default riftroute link
}

const resolvectlLink = "lo"

func (m *resolvectlManager) linkName() string {
	if m.link != "" {
		return m.link
	}
	return resolvectlLink
}

func (resolvectlManager) Backend() string { return "resolvectl" }

func (m *resolvectlManager) Apply(ctx context.Context, routes []domain.SplitDNSRoute) error {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	link := m.linkName()
	// Always start from a clean slate so removed domains/resolvers don't linger.
	_, _ = exec.CommandContext(cctx, "resolvectl", "revert", link).CombinedOutput()
	if len(routes) == 0 {
		return nil
	}
	for _, args := range resolvectlApplyArgs(link, routes) {
		out, err := exec.CommandContext(cctx, "resolvectl", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("resolvectl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func (m *resolvectlManager) Clear(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, _ = exec.CommandContext(cctx, "resolvectl", "revert", m.linkName()).CombinedOutput()
	return nil
}

// resolvectlServer renders a systemd-resolved DNS server address, honoring a
// non-standard port (the learner proxy binds a dynamic one). systemd-resolved
// accepts the "ADDRESS:PORT" form for IPv4 and "[ADDRESS]:PORT" for IPv6.
func resolvectlServer(resolver string, port int) string {
	if port <= 0 {
		return resolver
	}
	if strings.Contains(resolver, ":") { // IPv6 literal
		return fmt.Sprintf("[%s]:%d", resolver, port)
	}
	return fmt.Sprintf("%s:%d", resolver, port)
}

// resolvectlApplyArgs builds the ordered resolvectl invocations (arg-arrays,
// no shell) that install routes on link: the union of resolvers as the link's
// servers, and every domain as a routing-only domain ("~domain", which covers
// subdomains). Pure — unit-tested.
func resolvectlApplyArgs(link string, routes []domain.SplitDNSRoute) [][]string {
	var servers []string
	seenSrv := map[string]bool{}
	var domains []string
	seenDom := map[string]bool{}
	for _, r := range routes {
		srv := resolvectlServer(r.Resolver, r.Port)
		if !seenSrv[srv] {
			seenSrv[srv] = true
			servers = append(servers, srv)
		}
		d := domain.DomainRuleHost(r.Domain)
		if !seenDom[d] {
			seenDom[d] = true
			domains = append(domains, "~"+d)
		}
	}
	return [][]string{
		append([]string{"dns", link}, servers...),
		append([]string{"domain", link}, domains...),
	}
}

// Composed merges the user's split-DNS selection with daemon-generated
// routes (the wildcard learner's resolver-file entries) behind the Manager
// interface, so both write through ONE owner of /etc/resolver — two managers
// would clear each other's files.
type Composed struct {
	inner Manager
	extra func() []domain.SplitDNSRoute

	mu      sync.Mutex // guards user AND serializes inner writes (non-atomic)
	user    []domain.SplitDNSRoute
	applyMu sync.Mutex // serializes inner.Apply (Clear+write is not atomic)
}

// NewComposed wraps inner; extra() supplies the daemon's additional routes at
// every (re)apply. extra may return nil.
func NewComposed(inner Manager, extra func() []domain.SplitDNSRoute) *Composed {
	return &Composed{inner: inner, extra: extra}
}

func (c *Composed) Backend() string { return c.inner.Backend() }

// Apply records the USER selection and writes user+extra through.
func (c *Composed) Apply(ctx context.Context, routes []domain.SplitDNSRoute) error {
	c.mu.Lock()
	c.user = append([]domain.SplitDNSRoute{}, routes...)
	c.mu.Unlock()
	return c.Resync(ctx)
}

// Resync rewrites user+extra (call when the extra set changes). User routes
// take precedence: an extra (learner) route for a domain the user already
// configured is dropped, so a wildcard never silently clobbers an explicit
// split-DNS resolver for the same domain.
func (c *Composed) Resync(ctx context.Context) error {
	c.mu.Lock()
	merged := dedupePreferUser(c.user, extraOf(c.extra))
	c.mu.Unlock()
	return c.applyLocked(ctx, merged)
}

// ApplyUserOnly rewrites just the user selection — the shutdown path, so no
// resolver file is left pointing at a proxy that no longer exists.
func (c *Composed) ApplyUserOnly(ctx context.Context) error {
	c.mu.Lock()
	user := append([]domain.SplitDNSRoute{}, c.user...)
	c.mu.Unlock()
	return c.applyLocked(ctx, user)
}

func (c *Composed) Clear(ctx context.Context) error {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	return c.inner.Clear(ctx)
}

// applyLocked serializes the non-atomic inner Clear+write so two concurrent
// Resyncs can't interleave and leave a partial resolver set.
func (c *Composed) applyLocked(ctx context.Context, routes []domain.SplitDNSRoute) error {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	return c.inner.Apply(ctx, routes)
}

func extraOf(fn func() []domain.SplitDNSRoute) []domain.SplitDNSRoute {
	if fn == nil {
		return nil
	}
	return fn()
}

// dedupePreferUser returns user routes plus any extra route whose domain
// (apex-normalized) the user hasn't already claimed — user wins collisions.
func dedupePreferUser(user, extra []domain.SplitDNSRoute) []domain.SplitDNSRoute {
	claimed := map[string]bool{}
	out := make([]domain.SplitDNSRoute, 0, len(user)+len(extra))
	for _, r := range user {
		claimed[domain.DomainRuleHost(r.Domain)] = true
		out = append(out, r)
	}
	for _, r := range extra {
		if claimed[domain.DomainRuleHost(r.Domain)] {
			continue // user config wins this domain
		}
		out = append(out, r)
	}
	return out
}

// FakeManager records applied routes for tests / the fake provider.
type FakeManager struct {
	mu      sync.Mutex
	Applied []domain.SplitDNSRoute
}

func (f *FakeManager) Backend() string { return "fake" }
func (f *FakeManager) Apply(_ context.Context, routes []domain.SplitDNSRoute) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Applied = append([]domain.SplitDNSRoute{}, routes...)
	return nil
}
func (f *FakeManager) Clear(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Applied = nil
	return nil
}
