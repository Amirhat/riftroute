// Package perapp implements the classification half of per-app routing (spec
// §6, Linux only): it marks a cgroup v2's egress packets with the per-app fwmark
// so policy routing (`ip rule fwmark X lookup T`, emitted by the engine) steers
// that app's traffic into the tunnel table. The routing half lives in the engine;
// placing an app into the cgroup is the operator's job (or a future launcher).
//
// The nft ruleset generator is pure and unit-tested; real application is
// exec-only and Linux-only. macOS has no cgroup/fwmark equivalent (gated by
// Capabilities.PerAppRouting).
package perapp

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const markTable = "riftroute_mark"

// Marker installs/removes the cgroup→fwmark classification.
type Marker interface {
	Mark(ctx context.Context, cgroups []string, mark string) error
	Unmark(ctx context.Context) error
	Backend() string
}

// New returns the per-OS marker (nftables on Linux; unsupported elsewhere).
func New() Marker {
	if runtime.GOOS == "linux" {
		return &nftMarker{}
	}
	return &nftMarker{unsupported: true}
}

// BuildNftMarkRuleset renders the nft script that marks each cgroup's egress
// packets with mark (e.g. "0x5252"). cgroups are v2 paths relative to the
// unified hierarchy, e.g. "system.slice/myapp.service".
func BuildNftMarkRuleset(cgroups []string, mark string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", markTable)
	b.WriteString("  chain mark {\n")
	b.WriteString("    type route hook output priority -150; policy accept;\n")
	for _, cg := range cgroups {
		fmt.Fprintf(&b, "    socket cgroupv2 level 2 \"%s\" meta mark set %s\n", cg, mark)
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

type nftMarker struct{ unsupported bool }

func (m *nftMarker) Backend() string {
	if m.unsupported {
		return "unsupported"
	}
	return "nftables"
}

func (m *nftMarker) Mark(ctx context.Context, cgroups []string, mark string) error {
	if m.unsupported {
		return fmt.Errorf("per-app routing requires Linux (cgroup v2 + fwmark)")
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "nft", "-f", "-")
	cmd.Stdin = bytes.NewReader([]byte(BuildNftMarkRuleset(cgroups, mark)))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft mark: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *nftMarker) Unmark(ctx context.Context) error {
	if m.unsupported {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, _ = exec.CommandContext(cctx, "nft", "delete", "table", "inet", markTable).CombinedOutput()
	return nil
}

// FakeMarker is an in-memory marker for tests.
type FakeMarker struct {
	Marked  []string
	Enabled bool
}

func (f *FakeMarker) Backend() string { return "fake" }
func (f *FakeMarker) Mark(_ context.Context, cgroups []string, _ string) error {
	f.Marked = append([]string{}, cgroups...)
	f.Enabled = true
	return nil
}
func (f *FakeMarker) Unmark(_ context.Context) error {
	f.Marked = nil
	f.Enabled = false
	return nil
}
