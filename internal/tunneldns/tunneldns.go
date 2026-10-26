// Package tunneldns applies a full tunnel's DNS servers to the system while
// it's connected, and puts the system's own back when it isn't
// (docs/tunnels-full.md, "DNS: the tunnel's own"): systemd-resolved on Linux,
// the primary service's DNS in the dynamic store on macOS. Every change is
// recorded where a crashed daemon's successor finds it (Recover).
package tunneldns

import (
	"bytes"
	"context"
	"net/netip"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

// Applier applies a full tunnel's DNS to the system.
type Applier interface {
	// Backend names the mechanism, for status and doctor.
	Backend() string
	// Apply makes cfg the system's DNS (an empty cfg reverts).
	Apply(ctx context.Context, cfg Config) error
	// Revert puts the system's own DNS back.
	Revert(ctx context.Context) error
	// Recover undoes what a run that didn't end cleanly left, before any
	// tunnel comes up.
	Recover(ctx context.Context) error
	// Note says what keeps what's applied from working as it should, or "":
	// another link that also takes every name (Linux), an owner that keeps
	// rewriting the service's DNS (macOS). inEffect is false when what was
	// applied isn't any more (macOS let the owner have it).
	Note() (note string, inEffect bool)
}

// Logf logs a change an Applier makes on its own (slog.Logger.Info).
type Logf func(msg string, args ...any)

// New is this OS's Applier; stateDir holds what Recover needs (Linux), and
// log is told what it does on its own (macOS: holding the swap). nil where
// there's none.
func New(stateDir string, log Logf) Applier {
	switch runtime.GOOS {
	case "darwin":
		return newScutil(execRun, log)
	case "linux":
		return newResolved(execRun, filepath.Join(stateDir, "tunnel-dns.link"))
	}
	return nil
}

// execRun runs a system tool: no shell, stdin as given.
func execRun(ctx context.Context, stdin, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// Fake records what it's asked, for tests and the fake provider.
type Fake struct {
	mu       sync.Mutex
	Applied  Config
	Tries    int // every Apply, failed ones too
	Applies  int
	Reverts  int
	Recovers int
	Err      error  // returned by Apply when set
	Noted    string // returned by Note
	LetGo    bool   // Note says what's applied isn't in effect
}

func (f *Fake) Backend() string { return "fake" }

func (f *Fake) Note() (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Noted, !f.LetGo
}

// Attempts is how many times Apply was called.
func (f *Fake) Attempts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Tries
}

// SetErr sets what Apply returns.
func (f *Fake) SetErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Err = err
}

func (f *Fake) Apply(_ context.Context, cfg Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Tries++
	if f.Err != nil {
		return f.Err
	}
	if cfg.Empty() {
		f.Applied = Config{}
		f.Reverts++
		return nil
	}
	f.Applied = cfg
	f.Applies++
	return nil
}

func (f *Fake) Revert(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Applied = Config{}
	f.Reverts++
	return nil
}

func (f *Fake) Recover(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Recovers++
	return nil
}

// Current is what's applied.
func (f *Fake) Current() Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Applied
}

// noteBox holds an Applier's Note, read without waiting for a change in
// progress (the manager asks while it reports status).
type noteBox struct{ v atomic.Value }

func (n *noteBox) set(s string) { n.v.Store(s) }

func (n *noteBox) get() string {
	s, _ := n.v.Load().(string)
	return s
}

// maxPerFamily is how many DNS servers of each family are used.
const maxPerFamily = 4

// Config is the DNS a tunnel's server (or configuration) gives.
type Config struct {
	Iface   string       // the tunnel's interface
	Servers []netip.Addr // in the server's order
	Search  []string     // search domains
}

// Empty reports whether there's nothing to apply.
func (c Config) Empty() bool { return len(c.Servers) == 0 }

// Equal reports whether two configs apply the same thing.
func (c Config) Equal(o Config) bool {
	return c.Iface == o.Iface && slices.Equal(c.Servers, o.Servers) && slices.Equal(c.Search, o.Search)
}

// Clean keeps usable server addresses, in order, without repeats: no
// loopback, unspecified, multicast or link-local one (a tunnel's DNS is
// reached through the tunnel), at most maxPerFamily of each family.
func Clean(in []netip.Addr) []netip.Addr {
	var out []netip.Addr
	n := map[bool]int{}
	for _, a := range in {
		a = a.Unmap().WithZone("")
		if !a.IsValid() || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() ||
			slices.Contains(out, a) || n[a.Is4()] >= maxPerFamily {
			continue
		}
		n[a.Is4()]++
		out = append(out, a)
	}
	return out
}
