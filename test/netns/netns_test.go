//go:build linux && netns

// Package netns runs the REAL Linux RouteProvider and the full Apply Protocol
// inside an isolated network namespace (spec §15) — the perfect "throwaway real
// state": real `ip` add/del/get/flush, asserted against real kernel state, fully
// offline and safe. Run with: go test -tags netns ./test/netns/...
//
// TestMain re-execs the test binary under `unshare -rn` (a fresh net+user
// namespace) so every `ip` subprocess the provider spawns lands in the isolated
// namespace and never touches the host table. Where namespaces are unavailable
// the suite skips cleanly.
package netns

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/killswitch"
	"github.com/Amirhat/riftroute/internal/provider/linux"
	"github.com/Amirhat/riftroute/internal/routing"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/store"
)

func TestMain(m *testing.M) {
	if os.Getenv("RR_NETNS") != "1" {
		// Probe namespace support; skip cleanly if unavailable.
		if exec.Command("unshare", "-rn", "true").Run() != nil {
			fmt.Println("netns: user/net namespaces unavailable; skipping")
			os.Exit(0)
		}
		args := append([]string{"-rn", os.Args[0]}, os.Args[1:]...)
		cmd := exec.Command("unshare", args...)
		cmd.Env = append(os.Environ(), "RR_NETNS=1")
		cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
		err := cmd.Run()
		if err == nil {
			os.Exit(0)
		}
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		fmt.Println("netns re-exec error:", err)
		os.Exit(1)
	}
	setupNamespace()
	os.Exit(m.Run())
}

// setupNamespace builds a minimal topology inside the fresh namespace: lo up and
// a dummy interface with an on-link subnet so routes have a valid next hop.
func setupNamespace() {
	mustIP("link", "set", "lo", "up")
	mustIP("link", "add", "dummy0", "type", "dummy")
	mustIP("addr", "add", "10.0.0.1/24", "dev", "dummy0")
	mustIP("link", "set", "dummy0", "up")
}

func mustIP(args ...string) {
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		fmt.Printf("setup: ip %v: %v: %s\n", args, err, out)
		os.Exit(1)
	}
}

const gw = "10.0.0.2" // on-link next hop within dummy0's subnet

func bypass(cidr string) []domain.ManagedRoute {
	return []domain.ManagedRoute{{
		Route:     domain.Route{DstCIDR: cidr, Gateway: gw, Iface: "dummy0", Family: domain.FamilyV4, Owner: domain.OwnerRiftRoute},
		ProfileID: "p1",
	}}
}

func newProtocol(t *testing.T) (*safety.Protocol, *linux.Provider, *safety.FakeClock, *safety.FakeProber) {
	t.Helper()
	prov := linux.New()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	clk := safety.NewFakeClock(time.Unix(0, 0))
	prober := safety.NewFakeProber()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := safety.NewProtocol(prov, st, clk, func() safety.Prober { return prober }, "linux", log)
	return p, prov, clk, prober
}

func opts(interactive bool) safety.Options {
	return safety.Options{
		Interactive: interactive, Anchors: []string{gw}, K: 1,
		ProbeInterval: time.Second, ConfirmTimeout: 15 * time.Second, GuardWindow: 30 * time.Second,
		Actor: domain.ActorCLI, PhysGW: netip.MustParseAddr("10.0.0.1"),
	}
}

func managedCount(t *testing.T, prov *linux.Provider) int {
	t.Helper()
	rs, err := prov.ListRoutes(context.Background(), domain.FamilyV4)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range rs {
		if r.Owner == domain.OwnerRiftRoute {
			n++
		}
	}
	return n
}

// Real provider: AddRoute installs a proto-tagged route; FlushOwned clears it.
func TestNetnsProviderAddListFlush(t *testing.T) {
	prov := linux.New()
	ctx := context.Background()
	mr := bypass("9.9.9.0/24")[0]
	if err := prov.AddRoute(ctx, mr); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	dec, err := prov.LookupRoute(ctx, netip.MustParseAddr("9.9.9.1"))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Iface != "dummy0" {
		t.Fatalf("route get should resolve via dummy0, got %+v", dec)
	}
	if err := prov.FlushOwned(ctx); err != nil {
		t.Fatalf("FlushOwned: %v", err)
	}
	if n := managedCount(t, prov); n != 0 {
		t.Fatalf("flush left %d managed routes", n)
	}
}

// Apply Protocol over the REAL provider: apply + confirm installs a real route.
func TestNetnsApplyConfirm(t *testing.T) {
	p, prov, _, _ := newProtocol(t)
	res, err := p.Apply(context.Background(), bypass("9.9.9.0/24"), nil, opts(true))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, err := p.Confirm(res.TxID); err != nil {
		t.Fatal(err)
	}
	if n := managedCount(t, prov); n != 1 {
		t.Fatalf("confirmed apply should leave 1 managed route, got %d", n)
	}
	_ = p.Panic(context.Background(), domain.ActorCLI)
}

// §2.5 on real state: anchor loss → watchdog rolls the real route back.
func TestNetnsWatchdogRollback(t *testing.T) {
	p, prov, clk, prober := newProtocol(t)
	prober.SetReachable(gw, false)
	res, err := p.Apply(context.Background(), bypass("9.9.9.0/24"), nil, opts(false))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if managedCount(t, prov) != 1 {
		t.Fatal("route should be installed before guard fires")
	}
	clk.Advance(time.Second)
	if result, _ := p.Wait(res.TxID); result != domain.TxRolledBack {
		t.Fatalf("watchdog should roll back, got %s", result)
	}
	if n := managedCount(t, prov); n != 0 {
		t.Fatalf("watchdog rollback left %d real routes", n)
	}
}

// Model B (include mode) on real kernel state: an `ip rule` selects a
// destination into a dedicated table whose default egresses the tunnel; panic
// flushes both the rule and the table.
func TestNetnsModelBInclude(t *testing.T) {
	// A stand-in tunnel: a dummy named wg0 is classified as a VPN interface.
	mustIP("link", "add", "wg0", "type", "dummy")
	mustIP("addr", "add", "10.9.0.1/24", "dev", "wg0")
	mustIP("link", "set", "wg0", "up")
	defer func() { _ = exec.Command("ip", "link", "del", "wg0").Run() }()

	p, prov, _, _ := newProtocol(t)
	ctx := context.Background()

	routes := []domain.ManagedRoute{{
		Route:     domain.Route{DstCIDR: "0.0.0.0/0", Iface: "wg0", Table: routing.ModelBTable, Family: domain.FamilyV4, Owner: domain.OwnerRiftRoute},
		ProfileID: "inc",
	}}
	rules := []domain.ManagedRule{{
		PolicyRule: domain.PolicyRule{Selector: "to 1.1.1.0/24", Table: routing.ModelBTable, Priority: routing.ModelBRulePrio, Family: domain.FamilyV4, Proto: "riftroute"},
		ProfileID:  "inc",
	}}

	res, err := p.Apply(ctx, routes, rules, opts(true))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, err := p.Confirm(res.TxID); err != nil {
		t.Fatal(err)
	}

	// The proto-tagged rule is present.
	prules, _ := prov.ListRules(ctx, domain.FamilyV4)
	sawRule := false
	for _, r := range prules {
		if r.Proto == "riftroute" && strings.Contains(r.Selector, "1.1.1.0/24") && r.Table == routing.ModelBTable {
			sawRule = true
		}
	}
	if !sawRule {
		t.Fatalf("include rule missing: %+v", prules)
	}
	// The dedicated table has the default route.
	if out, _ := exec.Command("ip", "route", "show", "table", routing.ModelBTable).CombinedOutput(); !strings.Contains(string(out), "default") {
		t.Fatalf("table %s missing default: %s", routing.ModelBTable, out)
	}

	// Panic clears both the rule and the dedicated table.
	if err := p.Panic(ctx, domain.ActorCLI); err != nil {
		t.Fatal(err)
	}
	prules, _ = prov.ListRules(ctx, domain.FamilyV4)
	for _, r := range prules {
		if r.Proto == "riftroute" {
			t.Fatalf("panic left a managed rule: %+v", r)
		}
	}
	if out, _ := exec.Command("ip", "route", "show", "table", routing.ModelBTable).CombinedOutput(); strings.TrimSpace(string(out)) != "" {
		t.Fatalf("panic left routes in table %s: %s", routing.ModelBTable, out)
	}
}

// Kill switch on real nftables inside the namespace: enable installs the table,
// disable removes it. Skips if nft is unavailable.
func TestNetnsKillSwitch(t *testing.T) {
	m := killswitch.New() // nftables backend on Linux
	ctx := context.Background()
	cfg := killswitch.Config{TunnelIfaces: []string{"dummy0"}, Gateway: "10.0.0.1", LANSubnets: []string{"10.0.0.0/24"}}
	if err := m.Enable(ctx, cfg); err != nil {
		t.Skipf("nftables unavailable in this environment: %v", err)
	}
	if on, _ := m.Enabled(ctx); !on {
		t.Fatal("kill switch should report enabled")
	}
	if err := m.Disable(ctx); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if on, _ := m.Enabled(ctx); on {
		t.Fatal("kill switch should report disabled after Disable")
	}
}

// Panic removes real managed routes and is idempotent.
func TestNetnsPanicIdempotent(t *testing.T) {
	p, prov, _, _ := newProtocol(t)
	res, _ := p.Apply(context.Background(), bypass("9.9.9.0/24"), nil, opts(true))
	_, _ = p.Confirm(res.TxID)
	ctx := context.Background()
	if err := p.Panic(ctx, domain.ActorCLI); err != nil {
		t.Fatal(err)
	}
	if n := managedCount(t, prov); n != 0 {
		t.Fatalf("panic left %d routes", n)
	}
	if err := p.Panic(ctx, domain.ActorCLI); err != nil {
		t.Fatalf("second panic errored: %v", err)
	}
}
