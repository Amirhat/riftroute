package tunnel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/tunneldns"
)

// A full tunnel (all traffic) is saved and reported as one, its input says
// so once it's connected, a client that doesn't send the setting keeps it,
// false turns it off, and it takes an IPv6 address when offered.
func TestSaveAllTraffic(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	on, off := true, false
	spec := infraSpec()
	spec.AllTraffic = &on
	st, err := h.m.Save(ctx, spec)
	if err != nil || !st.AllTraffic {
		t.Fatalf("saved: %+v, %v", st, err)
	}
	h.m.mu.Lock()
	needs := h.m.defs["infra"].needsIPv6()
	h.m.mu.Unlock()
	if !needs {
		t.Error("a full tunnel doesn't ask for IPv6")
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
	if in := h.lastApply(); len(in) != 1 || !in[0].AllTraffic || in[0].Iface == "" {
		t.Fatalf("inputs = %+v", in)
	}

	if st, err := h.m.Save(ctx, infraSpec()); err != nil || !st.AllTraffic {
		t.Fatalf("an old client's edit dropped it: %+v, %v", st, err)
	}
	// Turning it off changes whether it asks for IPv6: that's settled at
	// connect, so it reconnects.
	starts := h.fl.Starts()
	spec.AllTraffic = &off
	if st, err := h.m.Save(ctx, spec); err != nil || st.AllTraffic {
		t.Fatalf("turned off: %+v, %v", st, err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
	if h.fl.Starts() == starts {
		t.Error("it didn't reconnect, so it still asks for IPv6")
	}
	if in := h.lastApply(); len(in) != 1 || in[0].AllTraffic {
		t.Fatalf("inputs after turning it off = %+v", in)
	}
}

// 0.0.0.0/0 as a listed route is still refused, and the reason points at
// the setting.
func TestDefaultRouteListedPointsAtAllTraffic(t *testing.T) {
	_, errs := normalizeRoutes([]string{"0.0.0.0/0"})
	if len(errs) != 1 || !strings.Contains(errs[0], "--all-traffic") {
		t.Fatalf("errs = %v", errs)
	}
}

// waitDNS waits for the DNS the system resolves with to be want ("" for its
// own).
func waitDNS(t *testing.T, h *harness, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		got := fmt.Sprint(h.dns.Current().Servers)
		if want == "" && h.dns.Current().Empty() || got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("DNS in use %s (on %q), want %s", got, h.dns.Current().Iface, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A full tunnel's DNS — its server's (the PUSH_REPLY), or the servers set
// for it — is the system's while it's connected, and the system's own comes
// back when it disconnects, or with a panic. A tunnel that lists networks
// never touches it.
func TestFullTunnelDNS(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	on := true
	spec := infraSpec()
	spec.AllTraffic = &on
	if _, err := h.m.Save(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
	waitDNS(t, h, "[10.99.0.1]")
	if h.dns.Current().Iface != "utun9" {
		t.Errorf("applied on %q", h.dns.Current().Iface)
	}
	if st, _ := h.m.Status("infra"); fmt.Sprint(st.DNS) != "[10.99.0.1]" || st.DNSNote != "" {
		t.Errorf("status DNS %v, note %q", st.DNS, st.DNSNote)
	}

	set := []string{"1.1.1.1", "2606:4700:4700::1111"}
	spec.DNS = &set
	if _, err := h.m.Save(ctx, spec); err != nil {
		t.Fatal(err)
	}
	h.m.Resync(ctx)
	waitDNS(t, h, "[1.1.1.1 2606:4700:4700::1111]")

	if err := h.m.Disconnect(ctx, "infra"); err != nil {
		t.Fatal(err)
	}
	waitDNS(t, h, "")

	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitDNS(t, h, "[1.1.1.1 2606:4700:4700::1111]")
	h.m.DisconnectAll() // a panic
	if !h.dns.Current().Empty() {
		t.Fatalf("a panic left the tunnel's DNS: %+v", h.dns.Current())
	}
}

// A full tunnel whose server gives no DNS leaves the system's own, and says
// so; one that lists networks never applies any.
func TestFullTunnelWithoutDNS(t *testing.T) {
	h := newHarness(t, func(f *FakeLauncher) { f.PushDNS = "-" })
	ctx := context.Background()
	on := true
	spec := infraSpec()
	spec.AllTraffic = &on
	if _, err := h.m.Save(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
	h.m.Resync(ctx)
	if st, _ := h.m.Status("infra"); len(st.DNS) != 0 || !strings.Contains(st.DNSNote, "gave no DNS servers") || h.dns.Applies != 0 {
		t.Fatalf("status DNS %v, note %q, applies %d", st.DNS, st.DNSNote, h.dns.Applies)
	}

	h2 := newHarness(t) // pushes 10.99.0.1, but lists networks
	if _, err := h2.m.Save(ctx, infraSpec()); err != nil {
		t.Fatal(err)
	}
	_ = h2.m.Connect("infra")
	waitState(t, h2.m, "infra", domain.TunnelConnected)
	h2.m.Resync(ctx)
	if h2.dns.Applies != 0 {
		t.Fatal("a tunnel that lists networks applied its DNS")
	}
}

// IKEv2: the server's DNS servers are read from charon-cmd's log, whose
// resolve plugin is loaded for a full tunnel's session only — and not by a
// strongSwan before 5.9.9 beside a resolvconf, which it would run whatever
// it's told: then the card says why, and the system's DNS stays.
func TestFullTunnelIKEv2DNS(t *testing.T) {
	h, fi := newIKEHarness(t)
	ctx := context.Background()
	fi.DNS = []string{"10.30.0.53", "10.30.0.54"}
	loadsResolve := func() bool {
		started := fi.Started()
		conf, err := os.ReadFile(started[len(started)-1].Conf)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Contains(string(conf), "resolve")
	}
	connect := func() {
		t.Helper()
		if err := h.m.Connect("office"); err != nil {
			t.Fatal(err)
		}
		waitState(t, h.m, "office", domain.TunnelConnected)
	}
	disconnect := func() {
		t.Helper()
		if err := h.m.Disconnect(ctx, "office"); err != nil {
			t.Fatal(err)
		}
		waitDNS(t, h, "")
	}
	spec := ikeSpec(t, newTestPKI(t))
	if _, err := h.m.Save(ctx, spec); err != nil {
		t.Fatal(err)
	}
	connect()
	if loadsResolve() {
		t.Error("a tunnel that lists networks loads the resolve plugin")
	}
	disconnect()

	on := true
	spec.AllTraffic = &on
	if _, err := h.m.Save(ctx, spec); err != nil {
		t.Fatal(err)
	}
	connect()
	if !loadsResolve() {
		t.Error("a full tunnel's session doesn't load the resolve plugin")
	}
	waitDNS(t, h, "[10.30.0.53 10.30.0.54]")
	disconnect()

	old := systemResolvconf
	t.Cleanup(func() { systemResolvconf = old })
	systemResolvconf = filepath.Join(t.TempDir(), "resolvconf")
	if err := os.WriteFile(systemResolvconf, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	fi.Version = "5.9.8"
	applies := h.dns.Applies
	connect()
	h.m.Resync(ctx)
	if st, _ := h.m.Status("office"); loadsResolve() || len(st.DNS) != 0 || !strings.Contains(st.DNSNote, "resolvconf") || h.dns.Applies != applies {
		t.Fatalf("5.9.8 beside resolvconf: resolve loaded %v, DNS %v, note %q", loadsResolve(), st.DNS, st.DNSNote)
	}
	disconnect()

	systemResolvconf = filepath.Join(t.TempDir(), "none") // it writes its own file then
	connect()
	waitDNS(t, h, "[10.30.0.53 10.30.0.54]")
	disconnect()
}

// A DNS change that fails (macOS between networks) is tried again on its
// own, not only at the next tunnel apply; and what the applier finds wrong
// later (another link taking every name) is on the card.
func TestFullTunnelDNSRetried(t *testing.T) {
	first := dnsRetryFirst
	dnsRetryFirst = 20 * time.Millisecond
	t.Cleanup(func() { dnsRetryFirst = first })
	h := newHarness(t)
	ctx := context.Background()
	h.dns.SetErr(errors.New("macOS has no primary network service to give the tunnel's DNS to"))
	on := true
	spec := infraSpec()
	spec.AllTraffic = &on
	if _, err := h.m.Save(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
	h.m.Resync(ctx)
	if st, _ := h.m.Status("infra"); len(st.DNS) != 0 || !strings.Contains(st.DNSNote, "no primary network service") {
		t.Fatalf("failed: DNS %v, note %q", st.DNS, st.DNSNote)
	}
	h.dns.SetErr(nil)
	waitDNS(t, h, "[10.99.0.1]")
	h.dns.Noted = "DNS also goes to tailscale0, which takes every name too"
	if st, _ := h.m.Status("infra"); !strings.Contains(st.DNSNote, "tailscale0") || len(st.DNS) == 0 {
		t.Fatalf("the applier's note isn't on the card: %q, DNS %v", st.DNSNote, st.DNS)
	}
	// Let go (macOS: the owner keeps rewriting it), the servers aren't in
	// use: only the note.
	h.dns.Noted, h.dns.LetGo = "the network service keeps rewriting its DNS", true
	if st, _ := h.m.Status("infra"); len(st.DNS) != 0 || !strings.Contains(st.DNSNote, "keeps rewriting") {
		t.Fatalf("let go: DNS %v, note %q", st.DNS, st.DNSNote)
	}
	h.dns.Noted, h.dns.LetGo = "", false

	// Without systemd-resolved, nothing will change: not tried again.
	if err := h.m.Disconnect(ctx, "infra"); err != nil {
		t.Fatal(err)
	}
	waitDNS(t, h, "")
	h.dns.SetErr(tunneldns.ErrUnavailable)
	if err := h.m.Connect("infra"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, "infra", domain.TunnelConnected)
	h.m.Resync(ctx)
	tries := h.dns.Attempts()
	time.Sleep(10 * dnsRetryFirst)
	if h.dns.Attempts() != tries {
		t.Errorf("an unavailable resolver was tried again: %d, then %d", tries, h.dns.Attempts())
	}
}
