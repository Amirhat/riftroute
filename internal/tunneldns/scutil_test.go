package tunneldns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeStore emulates the dynamic store behind scutil, for the commands the
// applier sends: show, list, get, set, remove, d.init, d.add, d.remove.
type fakeStore struct {
	mu   sync.Mutex
	keys map[string]map[string][]string // key → field → values (a scalar is one value)
	arr  map[string]map[string]bool     // key → field → is an array
	ran  []string                       // other commands run
}

func newFakeStore() *fakeStore {
	return &fakeStore{keys: map[string]map[string][]string{}, arr: map[string]map[string]bool{}}
}

func (f *fakeStore) put(key string, fields map[string][]string) {
	f.keys[key] = map[string][]string{}
	f.arr[key] = map[string]bool{}
	for k, v := range fields {
		f.keys[key][k] = v
		f.arr[key][k] = true
	}
}

func (f *fakeStore) servers(key string) []string { return f.keys[key]["ServerAddresses"] }

func (f *fakeStore) run(_ context.Context, stdin, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if name != "scutil" {
		f.ran = append(f.ran, name+" "+strings.Join(args, " "))
		return "", nil
	}
	var out strings.Builder
	d, darr := map[string][]string{}, map[string]bool{}
	for _, line := range strings.Split(stdin, "\n") {
		f2 := strings.Fields(line)
		if len(f2) == 0 {
			continue
		}
		for i, v := range f2 {
			if v == `""` { // scutil's empty string
				f2[i] = ""
			}
		}
		switch f2[0] {
		case "open", "close":
		case "show":
			fields, ok := f.keys[f2[1]]
			if !ok {
				out.WriteString("  No such key\n")
				continue
			}
			out.WriteString("<dictionary> {\n")
			names := make([]string, 0, len(fields))
			for k := range fields {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				if f.arr[f2[1]][k] {
					fmt.Fprintf(&out, "  %s : <array> {\n", k)
					for i, v := range fields[k] {
						fmt.Fprintf(&out, "    %d : %s\n", i, v)
					}
					out.WriteString("  }\n")
				} else {
					fmt.Fprintf(&out, "  %s : %s\n", k, fields[k][0])
				}
			}
			out.WriteString("}\n")
		case "list":
			re := regexp.MustCompile("^" + f2[1] + "$")
			var ks []string
			for k := range f.keys {
				if re.MatchString(k) {
					ks = append(ks, k)
				}
			}
			sort.Strings(ks)
			for i, k := range ks {
				fmt.Fprintf(&out, "  subKey [%d] = %s\n", i, k)
			}
		case "get":
			if fields, ok := f.keys[f2[1]]; ok {
				d, darr = map[string][]string{}, map[string]bool{}
				for k, v := range fields {
					d[k], darr[k] = slices.Clone(v), f.arr[f2[1]][k]
				}
			}
		case "set":
			f.keys[f2[1]], f.arr[f2[1]] = map[string][]string{}, map[string]bool{}
			for k, v := range d {
				f.keys[f2[1]][k], f.arr[f2[1]][k] = slices.Clone(v), darr[k]
			}
		case "remove":
			delete(f.keys, f2[1])
			delete(f.arr, f2[1])
		case "d.init":
			d, darr = map[string][]string{}, map[string]bool{}
		case "d.remove":
			delete(d, f2[1])
			delete(darr, f2[1])
		case "d.add":
			switch {
			case len(f2) >= 3 && f2[2] == "*":
				d[f2[1]], darr[f2[1]] = f2[3:], true
			case len(f2) >= 4 && f2[2] == "#":
				d[f2[1]], darr[f2[1]] = f2[3:4], false
			default:
				d[f2[1]], darr[f2[1]] = f2[2:3], false
			}
		}
	}
	return out.String(), nil
}

// noteOf is an Applier's note, without whether what's applied is in effect.
func noteOf(a Applier) string {
	n, _ := a.Note()
	return n
}

const (
	wifi = "11111111-AAAA-BBBB-CCCC-000000000001"
	eth  = "22222222-AAAA-BBBB-CCCC-000000000002"
)

func tunnelCfg() Config {
	return Config{Iface: "utun9", Servers: []netip.Addr{netip.MustParseAddr("10.8.0.1"), netip.MustParseAddr("10.8.0.2")}, Search: []string{"corp.example"}}
}

const vpn = "33333333-AAAA-BBBB-CCCC-000000000003" // an NE VPN that takes every domain

// storeWithVPN is Wi-Fi with its own DNS beside an NE VPN that takes DNS for
// every domain, as the owner's Mac has it.
func storeWithVPN() *fakeStore {
	f := newFakeStore()
	f.put(serviceDNS(wifi), map[string][]string{"ServerAddresses": {"192.168.88.1"}})
	f.put(serviceDNS(vpn), map[string][]string{"ServerAddresses": {"10.184.16.1"}, "SupplementalMatchDomains": {""}})
	f.keys[serviceDNS(vpn)]["InterfaceName"], f.arr[serviceDNS(vpn)]["InterfaceName"] = []string{"utun8"}, false
	return f
}

// upstream is a DNS server on loopback that answers every query with the
// query itself, marked a response: the tunnel's server, for the forwarder.
func upstream(t *testing.T) (netip.Addr, int) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n > 2 {
				buf[2] |= 0x80 // QR
				_, _ = pc.WriteTo(buf[:n], addr)
			}
		}
	}()
	return netip.MustParseAddr("127.0.0.1"), pc.LocalAddr().(*net.UDPAddr).Port
}

// newTestScutil is the applier on f, its forwarder asking up.
func newTestScutil(t *testing.T, f *fakeStore) (*scutilApplier, Config) {
	t.Helper()
	a, port := upstream(t)
	s := newScutil(f.run, nil)
	s.upstreamPort = port
	cfg := tunnelCfg()
	cfg.Servers = []netip.Addr{a}
	t.Cleanup(func() { _ = s.Revert(context.Background()) })
	return s, cfg
}

// ask sends a DNS query to the forwarder and says whether it was answered.
func ask(t *testing.T, port string) bool {
	t.Helper()
	c, err := net.Dial("udp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	q := []byte{0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	return err == nil && n == len(q) && buf[0] == 0x12 && buf[1] == 0x34 && buf[2]&0x80 != 0
}

// Ours is a resolver for every domain at the forwarder on loopback, which
// asks the tunnel's servers; the NE VPN's claim on every domain is set
// aside, Wi-Fi's DNS isn't touched; and a revert puts it all back.
func TestScutilResolverAtTheForwarder(t *testing.T) {
	f := storeWithVPN()
	s, cfg := newTestScutil(t, f)
	ctx := context.Background()
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	ours := f.keys[ourKey]
	port := fmt.Sprint(ours["ServerPort"][0])
	if fmt.Sprint(ours["ServerAddresses"]) != "[127.0.0.1]" || fmt.Sprintf("%q", ours["SupplementalMatchDomains"]) != `[""]` ||
		fmt.Sprint(ours["SearchDomains"]) != "[corp.example]" || port == "0" {
		t.Fatalf("our resolver %q", ours)
	}
	if !ask(t, port) {
		t.Fatal("the forwarder didn't answer from the tunnel's server")
	}
	if _, ok := f.keys[serviceDNS(vpn)]["SupplementalMatchDomains"]; ok {
		t.Errorf("the VPN still takes every domain: %v", f.keys[serviceDNS(vpn)])
	}
	if fmt.Sprint(f.keys[serviceDNS(vpn)]["ServerAddresses"]) != "[10.184.16.1]" || fmt.Sprint(f.keys[serviceDNS(wifi)]) != "map[ServerAddresses:[192.168.88.1]]" {
		t.Errorf("servers touched: VPN %v, Wi-Fi %v", f.keys[serviceDNS(vpn)], f.keys[serviceDNS(wifi)])
	}
	if err := s.Revert(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.keys[ourKey]; ok {
		t.Error("our resolver stayed")
	}
	if fmt.Sprintf("%q", f.keys[serviceDNS(vpn)]["SupplementalMatchDomains"]) != `[""]` || fmt.Sprint(f.keys[serviceDNS(vpn)]["InterfaceName"]) != "[utun8]" {
		t.Errorf("the VPN's claim isn't back: %q", f.keys[serviceDNS(vpn)])
	}
	for k := range f.keys {
		if strings.HasPrefix(k, "State:/Network/RiftRoute/") {
			t.Errorf("left %s", k)
		}
	}
	if !slices.Contains(f.ran, "killall -HUP mDNSResponder") {
		t.Errorf("caches not flushed: %v", f.ran)
	}
	if ask(t, port) {
		t.Error("the forwarder still answers after the revert")
	}
}

// A daemon that crashed with ours in place: its successor's Recover removes
// it (its forwarder went with the crash) and gives the VPN its claim back.
func TestScutilRecoverAfterACrash(t *testing.T) {
	f := storeWithVPN()
	s, cfg := newTestScutil(t, f)
	_ = s.Apply(context.Background(), cfg) // and the daemon dies
	if err := newScutil(f.run, nil).Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.keys[ourKey]; ok || fmt.Sprintf("%q", f.keys[serviceDNS(vpn)]["SupplementalMatchDomains"]) != `[""]` {
		t.Fatalf("not recovered: ours %v, VPN %q", f.keys[ourKey], f.keys[serviceDNS(vpn)])
	}
	if _, ok := f.keys[appliedKey]; ok {
		t.Error("the applied record stayed")
	}
}

// While ours is in place: the VPN taking every domain back (it reconnected)
// is set aside again, its new DNS the backup; ours, gone, is put back.
func TestScutilRecheck(t *testing.T) {
	f := storeWithVPN()
	s, cfg := newTestScutil(t, f)
	ctx := context.Background()
	_ = s.Apply(ctx, cfg)
	f.put(serviceDNS(vpn), map[string][]string{"ServerAddresses": {"10.184.16.9"}, "SupplementalMatchDomains": {""}}) // reconnected
	delete(f.keys, ourKey)
	s.recheck(ctx)
	if _, ok := f.keys[serviceDNS(vpn)]["SupplementalMatchDomains"]; ok || f.keys[ourKey] == nil {
		t.Fatalf("after the VPN reconnected: VPN %q, ours %v", f.keys[serviceDNS(vpn)], f.keys[ourKey])
	}
	if fmt.Sprint(f.servers(backupPrefix+vpn)) != "[10.184.16.9]" {
		t.Errorf("backup %v", f.servers(backupPrefix+vpn))
	}
	_ = s.Revert(ctx)
	if fmt.Sprint(f.servers(serviceDNS(vpn))) != "[10.184.16.9]" || fmt.Sprintf("%q", f.keys[serviceDNS(vpn)]["SupplementalMatchDomains"]) != `[""]` {
		t.Fatalf("restored %q", f.keys[serviceDNS(vpn)])
	}
}

// A restore leaves a service that took every domain back by itself, or went
// away, as it is; one that takes other domains beside every one loses ""
// alone, and gets it back.
func TestScutilRestoreLeavesWhatChanged(t *testing.T) {
	f := storeWithVPN()
	f.put(serviceDNS(eth), map[string][]string{"ServerAddresses": {"10.30.0.53"}, "SupplementalMatchDomains": {"", "corp.example"}})
	s, cfg := newTestScutil(t, f)
	ctx := context.Background()
	_ = s.Apply(ctx, cfg)
	if fmt.Sprintf("%q", f.keys[serviceDNS(eth)]["SupplementalMatchDomains"]) != `["corp.example"]` {
		t.Fatalf("set aside: %q", f.keys[serviceDNS(eth)])
	}
	delete(f.keys, serviceDNS(vpn)) // the VPN disconnected
	_ = s.Revert(ctx)
	if _, ok := f.keys[serviceDNS(vpn)]; ok {
		t.Error("a service that went came back")
	}
	if fmt.Sprintf("%q", f.keys[serviceDNS(eth)]["SupplementalMatchDomains"]) != `["" "corp.example"]` {
		t.Errorf("restored %q", f.keys[serviceDNS(eth)])
	}
}

// A service that keeps taking every domain back is let have it after
// maxRewrites: ours goes, its claim stays, the note says why, and the
// card's servers aren't in effect.
func TestScutilLetsAKeenClaimantHaveIt(t *testing.T) {
	f := storeWithVPN()
	s, cfg := newTestScutil(t, f)
	clock := time.Now()
	s.now = func() time.Time { return clock }
	ctx := context.Background()
	_ = s.Apply(ctx, cfg)
	for i := 1; i <= maxRewrites; i++ {
		f.keys[serviceDNS(vpn)]["SupplementalMatchDomains"], f.arr[serviceDNS(vpn)]["SupplementalMatchDomains"] = []string{""}, true
		clock = clock.Add(time.Minute)
		s.recheck(ctx)
		if _, inEffect := s.Note(); i < maxRewrites && !inEffect {
			t.Fatalf("let go after %d", i)
		}
	}
	n, inEffect := s.Note()
	if !strings.Contains(n, "keeps taking DNS for every domain back") || inEffect || f.keys[ourKey] != nil ||
		fmt.Sprintf("%q", f.keys[serviceDNS(vpn)]["SupplementalMatchDomains"]) != `[""]` {
		t.Fatalf("let go: note %q (in effect %v), ours %v, VPN %q", n, inEffect, f.keys[ourKey], f.keys[serviceDNS(vpn)])
	}
	s.recheck(ctx)
	if f.keys[ourKey] != nil {
		t.Error("put back after letting it go")
	}
}

// Linux: systemd-resolved on the tunnel's link, recorded for Recover.
func TestResolvedApplyRevertRecover(t *testing.T) {
	var ran []string
	ok := true
	run := func(_ context.Context, _, name string, args ...string) (string, error) {
		ran = append(ran, name+" "+strings.Join(args, " "))
		if args[0] == "status" && !ok {
			return "", fmt.Errorf("exit 1")
		}
		return "", nil
	}
	state := filepath.Join(t.TempDir(), "tunnel-dns.link")
	r := newResolved(run, state)
	ctx := context.Background()
	if err := r.Apply(ctx, tunnelCfg()); err != nil {
		t.Fatal(err)
	}
	want := []string{"resolvectl status utun9", "resolvectl dns utun9 10.8.0.1 10.8.0.2", "resolvectl domain utun9 ~. corp.example",
		"resolvectl default-route utun9 yes", "resolvectl domain"}
	if !slices.Equal(ran, want) {
		t.Fatalf("ran %q", ran)
	}
	if b, _ := os.ReadFile(state); strings.TrimSpace(string(b)) != "utun9" {
		t.Fatalf("state %q", b)
	}
	if noteOf(r) != "" {
		t.Errorf("note %q", noteOf(r))
	}
	ran = nil
	if err := newResolved(run, state).Recover(ctx); err != nil || !slices.Equal(ran, []string{"resolvectl revert utun9"}) {
		t.Fatalf("recover: %q %v", ran, err)
	}
	if _, err := os.Stat(state); err == nil {
		t.Error("the state file stayed")
	}
	ok = false
	if err := r.Apply(ctx, tunnelCfg()); err != ErrUnavailable {
		t.Fatalf("without resolved: %v", err)
	}
}

// Another link that also takes every name gets every query too: said, not
// changed. resolvectl before systemd 240 has no default-route: that's fine.
func TestResolvedAnotherLinkTakesEveryName(t *testing.T) {
	run := func(_ context.Context, _, name string, args ...string) (string, error) {
		switch {
		case args[0] == "default-route":
			return "Unknown operation default-route", fmt.Errorf("exit 1")
		case len(args) == 1 && args[0] == "domain":
			return "Global:\nLink 2 (eth0): corp.example\nLink 5 (utun9): ~. corp.example\nLink 7 (tailscale0): ~. ts.net\n", nil
		}
		return "", nil
	}
	r := newResolved(run, filepath.Join(t.TempDir(), "link"))
	if err := r.Apply(context.Background(), tunnelCfg()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(noteOf(r), "tailscale0") || strings.Contains(noteOf(r), "eth0") || strings.Contains(noteOf(r), "utun9") {
		t.Fatalf("note %q", noteOf(r))
	}
	if got := everyNameElsewhere("Global: ~.\nLink 3 (wg0): ~.\n", "wg0"); fmt.Sprint(got) != "[the global DNS setting]" {
		t.Errorf("global: %v", got)
	}
	_ = r.Revert(context.Background())
	if noteOf(r) != "" {
		t.Errorf("note after revert %q", noteOf(r))
	}
}

// A link that takes every name after the tunnel's DNS was applied
// (Tailscale started later) is said too, and no longer once it's gone; the
// looking stops with the revert.
func TestResolvedNotesALinkThatTakesEveryNameLater(t *testing.T) {
	every := noteEvery
	noteEvery = 10 * time.Millisecond
	t.Cleanup(func() { noteEvery = every })
	var mu sync.Mutex
	domains, asked := "Global:\nLink 5 (utun9): ~.\n", 0
	run := func(_ context.Context, _, name string, args ...string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if len(args) == 1 && args[0] == "domain" {
			asked++
			return domains, nil
		}
		return "", nil
	}
	set := func(v string) { mu.Lock(); domains = v; mu.Unlock() }
	count := func() int { mu.Lock(); defer mu.Unlock(); return asked }
	r := newResolved(run, filepath.Join(t.TempDir(), "link"))
	wait := func(what string, ok func() bool) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); !ok(); time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%s: note %q", what, noteOf(r))
			}
		}
	}
	ctx := context.Background()
	if err := r.Apply(ctx, tunnelCfg()); err != nil || noteOf(r) != "" {
		t.Fatalf("apply: %v, note %q", err, noteOf(r))
	}
	set("Global:\nLink 5 (utun9): ~.\nLink 7 (tailscale0): ~. ts.net\n")
	wait("tailscale0 taking every name later", func() bool { return strings.Contains(noteOf(r), "tailscale0") })
	set("Global:\nLink 5 (utun9): ~.\n")
	wait("tailscale0 gone", func() bool { return noteOf(r) == "" })
	_ = r.Revert(ctx)
	time.Sleep(20 * time.Millisecond) // a look already under way ends
	n := count()
	time.Sleep(50 * time.Millisecond)
	if count() != n || noteOf(r) != "" {
		t.Fatalf("still looking after the revert (%d → %d), note %q", n, count(), noteOf(r))
	}
}
