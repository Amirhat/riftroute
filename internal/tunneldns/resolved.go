package tunneldns

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
)

// Linux: systemd-resolved, on the tunnel's link — its servers, the routing
// domain "~." (every name), and the link as the default route for DNS. A
// lookup then matches the tunnel's link before any other's that has no
// domain of its own, so it goes there alone; split-DNS domains on other
// links, more specific, still go to them. Nothing else is touched:
// /etc/resolv.conf never. The link's name is recorded in a file, so a
// crashed daemon's successor reverts it (Recover); resolved forgets it
// anyway when the link goes.

// ErrUnavailable is Apply's error where nothing can apply a tunnel's DNS.
var ErrUnavailable = errors.New("systemd-resolved isn't running, so the tunnel's DNS can't be applied (RiftRoute never rewrites /etc/resolv.conf)")

var reLink = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

type resolvedApplier struct {
	run   runner
	state string // the file naming the link configured

	mu   sync.Mutex
	link string
}

func newResolved(run runner, state string) *resolvedApplier {
	return &resolvedApplier{run: run, state: state}
}

func (r *resolvedApplier) Backend() string { return "systemd-resolved" }

func (r *resolvedApplier) resolvectl(ctx context.Context, args ...string) error {
	if out, err := r.run(ctx, "", "resolvectl", args...); err != nil {
		return fmt.Errorf("resolvectl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(out))
	}
	return nil
}

// Apply points name resolution at cfg's servers, through its link.
func (r *resolvedApplier) Apply(ctx context.Context, cfg Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cfg.Empty() {
		return r.revertLocked(ctx)
	}
	if !reLink.MatchString(cfg.Iface) {
		return fmt.Errorf("bad interface name %q", cfg.Iface)
	}
	if _, err := r.run(ctx, "", "resolvectl", "status", cfg.Iface); err != nil {
		return ErrUnavailable
	}
	if r.link != "" && r.link != cfg.Iface {
		_ = r.resolvectl(ctx, "revert", r.link)
	}
	if err := os.WriteFile(r.state, []byte(cfg.Iface+"\n"), 0o600); err != nil {
		return fmt.Errorf("record the link: %w", err)
	}
	r.link = cfg.Iface
	if err := r.resolvectl(ctx, append([]string{"dns", cfg.Iface}, addrStrings(cfg.Servers)...)...); err != nil {
		return err
	}
	if err := r.resolvectl(ctx, append([]string{"domain", cfg.Iface, "~."}, cfg.Search...)...); err != nil {
		return err
	}
	return r.resolvectl(ctx, "default-route", cfg.Iface, "yes")
}

func (r *resolvedApplier) Revert(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revertLocked(ctx)
}

func (r *resolvedApplier) revertLocked(ctx context.Context) error {
	if r.link != "" {
		_ = r.resolvectl(ctx, "revert", r.link) // gone with its link is fine
		r.link = ""
	}
	_ = os.Remove(r.state)
	return nil
}

// Recover reverts the link a run that didn't end cleanly configured.
func (r *resolvedApplier) Recover(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, err := os.ReadFile(r.state)
	if err != nil {
		return nil
	}
	if link := strings.TrimSpace(string(b)); reLink.MatchString(link) {
		_ = r.resolvectl(ctx, "revert", link)
	}
	_ = os.Remove(r.state)
	return nil
}
