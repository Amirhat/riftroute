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
// the given resolver (pure; unit-tested).
func ResolverFile(resolver string) string {
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
		if err := os.WriteFile(path, []byte(ResolverFile(r.Resolver)), 0o644); err != nil {
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

type resolvectlManager struct{}

func (resolvectlManager) Backend() string { return "resolvectl" }

func (resolvectlManager) Apply(ctx context.Context, routes []domain.SplitDNSRoute) error {
	// Best-effort: point the primary link's per-domain resolver. Full per-domain
	// link selection is environment-specific; documented in packaging.
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for _, r := range routes {
		out, err := exec.CommandContext(cctx, "resolvectl", "dns", domain.DomainRuleHost(r.Domain), r.Resolver).CombinedOutput()
		if err != nil {
			return fmt.Errorf("resolvectl: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func (resolvectlManager) Clear(context.Context) error { return nil }

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
