package tunneldns

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Linux: systemd-resolved, on the tunnel's link — its servers, the routing
// domain "~." (every name), and the link as the default route for DNS. A
// lookup then matches the tunnel's link before any other's that has no
// domain of its own, so it goes there alone; split-DNS domains on other
// links, more specific, still go to them. Nothing else is touched:
// /etc/resolv.conf never. The link's name is recorded in a file, so a
// crashed daemon's successor reverts it (Recover); resolved forgets it
// anyway when the link goes.
//
// Another link that also has "~." (Tailscale overriding the local DNS, a
// NetworkManager VPN that takes all traffic) gets every name too: resolved
// asks both, and nothing outranks it. That's said (Note), not changed:
// the other link isn't RiftRoute's. It's looked for again every noteEvery
// while the tunnel's DNS is applied, so a link that takes every name later
// (Tailscale started after the tunnel) is said too.

// ErrUnavailable is Apply's error where nothing can apply a tunnel's DNS.
var ErrUnavailable = errors.New("systemd-resolved isn't running, so the tunnel's DNS can't be applied (RiftRoute never rewrites /etc/resolv.conf)")

var reLink = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// noteEvery is how often, while the tunnel's DNS is applied, the other links
// are looked at again for one that takes every name too.
var noteEvery = 30 * time.Second

type resolvedApplier struct {
	run   runner
	state string // the file naming the link configured

	mu   sync.Mutex
	link string
	note noteBox
	stop chan struct{} // ends watch
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
	// "~." already makes it the default route; resolvectl before systemd
	// 240 has no default-route to say so twice.
	_ = r.resolvectl(ctx, "default-route", cfg.Iface, "yes")
	out, _ := r.run(ctx, "", "resolvectl", "domain")
	r.note.set(elsewhereNote(out, cfg.Iface))
	if r.stop == nil {
		r.stop = make(chan struct{})
		go r.watch(r.stop, noteEvery)
	}
	return nil
}

// elsewhereNote is the note for `resolvectl domain`'s output: the links but
// iface that take every name too, or "".
func elsewhereNote(out, iface string) string {
	if others := everyNameElsewhere(out, iface); len(others) > 0 {
		return "DNS also goes to " + strings.Join(others, ", ") + ", which takes every name too: systemd-resolved asks both"
	}
	return ""
}

// watch looks at the other links again while the tunnel's DNS is applied.
func (r *resolvedApplier) watch(stop chan struct{}, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			r.mu.Lock()
			link := r.link
			r.mu.Unlock()
			if link == "" {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			out, err := r.run(ctx, "", "resolvectl", "domain")
			cancel()
			if err != nil {
				continue
			}
			r.mu.Lock()
			if r.link == link { // still applied there
				r.note.set(elsewhereNote(out, link))
			}
			r.mu.Unlock()
		}
	}
}

// Note says when another link takes every name too.
func (r *resolvedApplier) Note() (string, bool) { return r.note.get(), true }

// everyNameElsewhere reads `resolvectl domain` ("Global: …", "Link 3
// (eth0): …") for the links but iface whose domains include "~.".
func everyNameElsewhere(out, iface string) []string {
	var others []string
	for _, l := range strings.Split(out, "\n") {
		name, domains, ok := strings.Cut(l, ":")
		if !ok || !slices.Contains(strings.Fields(domains), "~.") {
			continue
		}
		name = strings.TrimSpace(name)
		if i, j := strings.IndexByte(name, '('), strings.IndexByte(name, ')'); i >= 0 && j > i {
			name = name[i+1 : j]
		}
		switch {
		case name == iface:
		case name == "Global":
			others = append(others, "the global DNS setting")
		default:
			others = append(others, name)
		}
	}
	return others
}

func (r *resolvedApplier) Revert(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revertLocked(ctx)
}

func (r *resolvedApplier) revertLocked(ctx context.Context) error {
	if r.stop != nil {
		close(r.stop)
		r.stop = nil
	}
	if r.link != "" {
		_ = r.resolvectl(ctx, "revert", r.link) // gone with its link is fine
		r.link = ""
	}
	r.note.set("")
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
