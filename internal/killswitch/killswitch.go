// Package killswitch blocks egress when the tunnel drops, so traffic never leaks
// to the physical network (spec §6/§7). Linux uses nftables (a dedicated inet
// table); macOS uses pf (a dedicated anchor). The rule generators are pure and
// unit-tested; real application is exec-only (arg-array) and is exercised against
// a network namespace in CI. The agent never enables it on a live host.
package killswitch

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Config is the allow-list the kill switch keeps open while blocking everything
// else outbound: loopback, the tunnel interface(s), and the path to the physical
// gateway/LAN so the VPN can reconnect (otherwise it's a permanent lockout).
type Config struct {
	TunnelIfaces []string
	Gateway      string
	LANSubnets   []string
}

// Manager enables/disables the kill switch and reports its state.
type Manager interface {
	Enable(ctx context.Context, cfg Config) error
	Disable(ctx context.Context) error
	Enabled(ctx context.Context) (bool, error)
	Backend() string // "nftables" | "pf" | "fake" | "unsupported"
}

// New returns the per-OS manager.
func New() Manager {
	switch runtime.GOOS {
	case "linux":
		return &realManager{backend: "nftables"}
	case "darwin":
		return &realManager{backend: "pf"}
	default:
		return &realManager{backend: "unsupported"}
	}
}

const (
	nftTable = "riftroute_ks"
	pfAnchor = "riftroute_ks"
	enableTO = 10 * time.Second
)

type realManager struct{ backend string }

func (m *realManager) Backend() string { return m.backend }

func (m *realManager) Enable(ctx context.Context, cfg Config) error {
	switch m.backend {
	case "nftables":
		return runStdin(ctx, NftRuleset(cfg), "nft", "-f", "-")
	case "pf":
		// Load the anchor rules; the anchor must be referenced from pf.conf and pf
		// enabled (`pfctl -e`) — documented in packaging. We load + enable here.
		if err := runStdin(ctx, PfRuleset(cfg), "pfctl", "-a", pfAnchor, "-f", "-"); err != nil {
			return err
		}
		_, _ = run(ctx, "pfctl", "-E") // enable pf (idempotent; -E ref-counts)
		return nil
	default:
		return fmt.Errorf("kill switch unsupported on %s", runtime.GOOS)
	}
}

func (m *realManager) Disable(ctx context.Context) error {
	switch m.backend {
	case "nftables":
		_, err := run(ctx, "nft", "delete", "table", "inet", nftTable)
		if err != nil && strings.Contains(err.Error(), "No such file") {
			return nil // already gone
		}
		return err
	case "pf":
		_, _ = run(ctx, "pfctl", "-a", pfAnchor, "-F", "all")
		return nil
	default:
		return nil
	}
}

func (m *realManager) Enabled(ctx context.Context) (bool, error) {
	switch m.backend {
	case "nftables":
		_, err := run(ctx, "nft", "list", "table", "inet", nftTable)
		return err == nil, nil
	case "pf":
		out, err := run(ctx, "pfctl", "-a", pfAnchor, "-s", "rules")
		if err != nil {
			return false, nil
		}
		return strings.TrimSpace(out) != "", nil
	default:
		return false, nil
	}
}

// NftRuleset renders the nftables script for the kill switch: an output chain
// defaulting to drop, with the allow-list opened.
func NftRuleset(cfg Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", nftTable)
	b.WriteString("  chain output {\n")
	b.WriteString("    type filter hook output priority 0; policy drop;\n")
	b.WriteString("    oif \"lo\" accept\n")
	b.WriteString("    ct state established,related accept\n")
	for _, ifn := range cfg.TunnelIfaces {
		fmt.Fprintf(&b, "    oifname \"%s\" accept\n", ifn)
	}
	if cfg.Gateway != "" {
		fmt.Fprintf(&b, "    ip daddr %s accept\n", cfg.Gateway)
	}
	for _, lan := range cfg.LANSubnets {
		fmt.Fprintf(&b, "    ip daddr %s accept\n", lan)
	}
	// DHCP + DNS-to-gateway so reconnect works.
	b.WriteString("    udp dport {67,68} accept\n")
	b.WriteString("  }\n}\n")
	return b.String()
}

// PfRuleset renders the pf anchor rules for the kill switch.
func PfRuleset(cfg Config) string {
	var b strings.Builder
	b.WriteString("set block-policy drop\n")
	b.WriteString("pass out quick on lo0 all\n")
	for _, ifn := range cfg.TunnelIfaces {
		fmt.Fprintf(&b, "pass out quick on %s all\n", ifn)
	}
	if cfg.Gateway != "" {
		fmt.Fprintf(&b, "pass out quick to %s\n", cfg.Gateway)
	}
	for _, lan := range cfg.LANSubnets {
		fmt.Fprintf(&b, "pass out quick to %s\n", lan)
	}
	b.WriteString("block out all\n")
	return b.String()
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, enableTO)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func runStdin(ctx context.Context, stdin, name string, args ...string) error {
	cctx, cancel := context.WithTimeout(ctx, enableTO)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Stdin = bytes.NewReader([]byte(stdin))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Fake is an in-memory kill switch for tests and the fake provider.
type Fake struct {
	mu sync.Mutex
	on bool
}

func (f *Fake) Backend() string { return "fake" }
func (f *Fake) Enable(_ context.Context, _ Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.on = true
	return nil
}
func (f *Fake) Disable(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.on = false
	return nil
}
func (f *Fake) Enabled(_ context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.on, nil
}
