package tunneldns

import (
	"context"
	"fmt"
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

func storeWithPrimary(svc string) *fakeStore {
	f := newFakeStore()
	f.put(globalIPv4, nil)
	f.keys[globalIPv4]["PrimaryService"] = []string{svc}
	f.put(serviceDNS(svc), map[string][]string{"ServerAddresses": {"192.168.1.1"}, "SupplementalMatchDomains": {""}})
	f.keys[serviceDNS(svc)]["InterfaceName"], f.arr[serviceDNS(svc)]["InterfaceName"] = []string{"utun8"}, false
	return f
}

// The swap: the primary service's servers become the tunnel's, its old
// dictionary is kept, and a revert puts it back and removes RiftRoute's keys.
func TestScutilSwapAndRestore(t *testing.T) {
	f := storeWithPrimary(wifi)
	s := newScutil(f.run, nil)
	ctx := context.Background()
	if err := s.Apply(ctx, tunnelCfg()); err != nil {
		t.Fatal(err)
	}
	defer s.Revert(ctx)
	if got := f.servers(serviceDNS(wifi)); fmt.Sprint(got) != "[10.8.0.1 10.8.0.2]" {
		t.Fatalf("primary's servers %v", got)
	}
	if got := f.keys[serviceDNS(wifi)]["SearchDomains"]; fmt.Sprint(got) != "[corp.example]" {
		t.Errorf("search domains %v", got)
	}
	// The plain default resolver, reached through the tunnel: a VPN's
	// supplemental one, scoped to its interface, never sends to it.
	if _, ok := f.keys[serviceDNS(wifi)]["SupplementalMatchDomains"]; ok || fmt.Sprint(f.keys[serviceDNS(wifi)]["InterfaceName"]) != "[utun9]" {
		t.Errorf("not the plain default resolver through the tunnel: %v", f.keys[serviceDNS(wifi)])
	}
	if got := f.servers(backupPrefix + wifi); fmt.Sprint(got) != "[192.168.1.1]" {
		t.Errorf("backup %v", got)
	}
	if err := s.Revert(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.servers(serviceDNS(wifi)); fmt.Sprint(got) != "[192.168.1.1]" {
		t.Fatalf("restored %v", got)
	}
	if _, ok := f.keys[serviceDNS(wifi)]["SearchDomains"]; ok {
		t.Error("the tunnel's search domains stayed")
	}
	if dns := f.keys[serviceDNS(wifi)]; fmt.Sprintf("%q %v", dns["SupplementalMatchDomains"], f.arr[serviceDNS(wifi)]["SupplementalMatchDomains"]) != `[""] true` ||
		fmt.Sprint(dns["InterfaceName"]) != "[utun8]" {
		t.Errorf("the interface and match domains aren't back: %q", dns)
	}
	for k := range f.keys {
		if strings.HasPrefix(k, "State:/Network/RiftRoute/") {
			t.Errorf("left %s", k)
		}
	}
	if !slices.Contains(f.ran, "killall -HUP mDNSResponder") {
		t.Errorf("caches not flushed: %v", f.ran)
	}
}

// A value the service's owner wrote while the swap was in place (a DHCP
// renewal, a VPN reconnecting) is theirs: a revert leaves it.
func TestScutilRestoreLeavesTheOwnersNewValue(t *testing.T) {
	f := storeWithPrimary(wifi)
	s := newScutil(f.run, nil)
	ctx := context.Background()
	_ = s.Apply(ctx, tunnelCfg())
	f.keys[serviceDNS(wifi)]["ServerAddresses"] = []string{"192.168.1.254"}
	_ = s.Revert(ctx)
	if got := f.servers(serviceDNS(wifi)); fmt.Sprint(got) != "[192.168.1.254]" {
		t.Fatalf("the owner's value was overwritten: %v", got)
	}
	if _, ok := f.keys[backupPrefix+wifi]; ok {
		t.Error("the backup stayed")
	}
}

// A service with no DNS of its own gets one for the swap, removed again.
func TestScutilServiceWithoutDNS(t *testing.T) {
	f := storeWithPrimary(wifi)
	delete(f.keys, serviceDNS(wifi))
	s := newScutil(f.run, nil)
	ctx := context.Background()
	_ = s.Apply(ctx, tunnelCfg())
	if fmt.Sprint(f.servers(serviceDNS(wifi))) != "[10.8.0.1 10.8.0.2]" {
		t.Fatalf("not swapped: %v", f.keys)
	}
	_ = s.Revert(ctx)
	if _, ok := f.keys[serviceDNS(wifi)]; ok {
		t.Fatal("the DNS created for the swap stayed")
	}
}

// A daemon that crashed with the swap in place: its successor's Recover
// puts the backup back before anything comes up.
func TestScutilRecoverAfterACrash(t *testing.T) {
	f := storeWithPrimary(wifi)
	_ = newScutil(f.run, nil).Apply(context.Background(), tunnelCfg()) // and the daemon dies
	if err := newScutil(f.run, nil).Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := f.servers(serviceDNS(wifi)); fmt.Sprint(got) != "[192.168.1.1]" {
		t.Fatalf("not recovered: %v", got)
	}
	if _, ok := f.keys[appliedKey]; ok {
		t.Error("the applied record stayed")
	}
}

// While the swap is in place: a new primary service gets it (the old one
// restored), and an owner's rewrite is backed up and swapped again.
func TestScutilRecheck(t *testing.T) {
	f := storeWithPrimary(wifi)
	f.put(serviceDNS(eth), map[string][]string{"ServerAddresses": {"10.0.0.1"}})
	s := newScutil(f.run, nil)
	ctx := context.Background()
	_ = s.Apply(ctx, tunnelCfg())
	defer s.Revert(ctx)

	f.keys[globalIPv4]["PrimaryService"] = []string{eth} // Ethernet plugged in
	s.recheck(ctx)
	if fmt.Sprint(f.servers(serviceDNS(wifi))) != "[192.168.1.1]" || fmt.Sprint(f.servers(serviceDNS(eth))) != "[10.8.0.1 10.8.0.2]" {
		t.Fatalf("after the primary changed: wifi %v, eth %v", f.servers(serviceDNS(wifi)), f.servers(serviceDNS(eth)))
	}

	f.keys[serviceDNS(eth)]["ServerAddresses"] = []string{"10.0.0.2"} // DHCP renewed it
	s.recheck(ctx)
	if fmt.Sprint(f.servers(serviceDNS(eth))) != "[10.8.0.1 10.8.0.2]" || fmt.Sprint(f.servers(backupPrefix+eth)) != "[10.0.0.2]" {
		t.Fatalf("after the owner's rewrite: %v, backup %v", f.servers(serviceDNS(eth)), f.servers(backupPrefix+eth))
	}
	_ = s.Revert(ctx)
	if fmt.Sprint(f.servers(serviceDNS(eth))) != "[10.0.0.2]" {
		t.Fatalf("restored the stale value: %v", f.servers(serviceDNS(eth)))
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

// A restore puts back what the swap changed — the servers, and search
// domains it set — into the service's DNS as it is, so what else its owner
// changed meanwhile stays.
func TestScutilRestoreKeepsTheOwnersOtherChanges(t *testing.T) {
	f := storeWithPrimary(wifi)
	f.keys[serviceDNS(wifi)]["SearchDomains"], f.arr[serviceDNS(wifi)]["SearchDomains"] = []string{"home.example"}, true
	s := newScutil(f.run, nil)
	ctx := context.Background()
	_ = s.Apply(ctx, tunnelCfg())
	f.keys[serviceDNS(wifi)]["DomainName"], f.arr[serviceDNS(wifi)]["DomainName"] = []string{"lan.example"}, false
	_ = s.Revert(ctx)
	dns := f.keys[serviceDNS(wifi)]
	if fmt.Sprint(dns["ServerAddresses"]) != "[192.168.1.1]" || fmt.Sprint(dns["SearchDomains"]) != "[home.example]" || fmt.Sprint(dns["DomainName"]) != "[lan.example]" {
		t.Fatalf("restored %v", dns)
	}
}

// An owner that keeps rewriting the service's DNS is let have it after
// maxRewrites: the swap stops, the note says why, and RiftRoute's keys go.
func TestScutilLetsAKeenOwnerHaveIt(t *testing.T) {
	f := storeWithPrimary(wifi)
	s := newScutil(f.run, nil)
	clock := time.Now()
	s.now = func() time.Time { return clock }
	ctx := context.Background()
	_ = s.Apply(ctx, tunnelCfg())
	defer s.Revert(ctx)
	for i := 1; i <= maxRewrites; i++ {
		f.keys[serviceDNS(wifi)]["ServerAddresses"] = []string{"192.168.1.1"}
		clock = clock.Add(time.Minute)
		s.recheck(ctx)
		swapped := fmt.Sprint(f.servers(serviceDNS(wifi))) == "[10.8.0.1 10.8.0.2]"
		if i < maxRewrites && (!swapped || noteOf(s) != "") {
			t.Fatalf("rewrite %d: swapped %v, note %q", i, swapped, noteOf(s))
		}
	}
	if _, inEffect := s.Note(); fmt.Sprint(f.servers(serviceDNS(wifi))) != "[192.168.1.1]" || !strings.Contains(noteOf(s), "keeps rewriting") || inEffect {
		t.Fatalf("after %d rewrites: %v, note %q (in effect %v)", maxRewrites, f.servers(serviceDNS(wifi)), noteOf(s), inEffect)
	}
	for k := range f.keys {
		if strings.HasPrefix(k, "State:/Network/RiftRoute/") {
			t.Errorf("left %s", k)
		}
	}
	s.recheck(ctx)
	if fmt.Sprint(f.servers(serviceDNS(wifi))) != "[192.168.1.1]" {
		t.Error("swapped again after letting it go")
	}
	// Rewrites far apart are each held.
	_ = s.Apply(ctx, Config{Iface: "utun9", Servers: []netip.Addr{netip.MustParseAddr("10.8.0.9")}})
	for i := 0; i < 2*maxRewrites; i++ {
		f.keys[serviceDNS(wifi)]["ServerAddresses"] = []string{"192.168.1.1"}
		clock = clock.Add(rewriteWindow / 2)
		s.recheck(ctx)
	}
	if fmt.Sprint(f.servers(serviceDNS(wifi))) != "[10.8.0.9]" || noteOf(s) != "" {
		t.Fatalf("slow rewrites: %v, note %q", f.servers(serviceDNS(wifi)), noteOf(s))
	}
}

// DNS servers set by hand are the service's Setup: DNS, which outranks its
// State: one: both are swapped, and both restored. When the preferences are
// applied again (configd puts the saved Setup: back), the recheck swaps it
// again, keeping State's backup as it was before the swap.
func TestScutilSwapsDNSSetByHand(t *testing.T) {
	f := storeWithPrimary(eth)
	f.put(serviceDNS(eth), map[string][]string{"ServerAddresses": {"192.168.88.1"}})
	f.put(setupDNS(eth), map[string][]string{"ServerAddresses": {"1.1.1.1"}})
	f.keys[globalIPv4]["PrimaryService"] = []string{eth}
	s := newScutil(f.run, nil)
	ctx := context.Background()
	if err := s.Apply(ctx, tunnelCfg()); err != nil {
		t.Fatal(err)
	}
	ours := "[10.8.0.1 10.8.0.2]"
	if fmt.Sprint(f.servers(serviceDNS(eth))) != ours || fmt.Sprint(f.servers(setupDNS(eth))) != ours {
		t.Fatalf("swapped: State %v, Setup %v", f.servers(serviceDNS(eth)), f.servers(setupDNS(eth)))
	}
	f.keys[setupDNS(eth)]["ServerAddresses"] = []string{"1.1.1.1"} // the preferences applied
	s.recheck(ctx)
	if fmt.Sprint(f.servers(setupDNS(eth))) != ours || fmt.Sprint(f.servers(backupPrefix+eth)) != "[192.168.88.1]" ||
		fmt.Sprint(f.servers(setupBackupPrefix+eth)) != "[1.1.1.1]" {
		t.Fatalf("after the preferences were applied: Setup %v, backups %v %v", f.servers(setupDNS(eth)),
			f.servers(backupPrefix+eth), f.servers(setupBackupPrefix+eth))
	}
	_ = newScutil(f.run, nil).Recover(ctx) // a crash, then the next start
	_ = s.Revert(ctx)
	if fmt.Sprint(f.servers(serviceDNS(eth))) != "[192.168.88.1]" || fmt.Sprint(f.servers(setupDNS(eth))) != "[1.1.1.1]" {
		t.Fatalf("restored: State %v, Setup %v", f.servers(serviceDNS(eth)), f.servers(setupDNS(eth)))
	}
	for k := range f.keys {
		if strings.HasPrefix(k, "State:/Network/RiftRoute/") {
			t.Errorf("left %s", k)
		}
	}

	// Let go after the preferences keep coming back: State's goes back too.
	_ = s.Apply(ctx, tunnelCfg())
	for i := 0; i < maxRewrites; i++ {
		f.keys[setupDNS(eth)]["ServerAddresses"] = []string{"1.1.1.1"}
		s.recheck(ctx)
	}
	if _, inEffect := s.Note(); inEffect || fmt.Sprint(f.servers(serviceDNS(eth))) != "[192.168.88.1]" || fmt.Sprint(f.servers(setupDNS(eth))) != "[1.1.1.1]" {
		t.Fatalf("let go: State %v, Setup %v, in effect %v", f.servers(serviceDNS(eth)), f.servers(setupDNS(eth)), inEffect)
	}
	for k := range f.keys {
		if strings.HasPrefix(k, "State:/Network/RiftRoute/") {
			t.Errorf("let go, left %s", k)
		}
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

// A plain primary (Wi-Fi, Ethernet: servers only) gets the servers alone —
// no interface named, nothing dropped — and a recheck takes it as held.
func TestScutilPlainPrimaryKeepsItsShape(t *testing.T) {
	f := storeWithPrimary(eth)
	f.put(serviceDNS(eth), map[string][]string{"ServerAddresses": {"192.168.88.1"}})
	f.keys[globalIPv4]["PrimaryService"] = []string{eth}
	s := newScutil(f.run, nil)
	ctx := context.Background()
	if err := s.Apply(ctx, tunnelCfg()); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.keys[serviceDNS(eth)]["InterfaceName"]; ok || fmt.Sprint(f.servers(serviceDNS(eth))) != "[10.8.0.1 10.8.0.2]" {
		t.Fatalf("plain primary reshaped: %v", f.keys[serviceDNS(eth)])
	}
	for i := 0; i < maxRewrites+1; i++ {
		s.recheck(ctx)
	}
	if n, inEffect := s.Note(); n != "" || !inEffect || len(s.rewrites) != 0 {
		t.Fatalf("held taken as rewritten: %q %v %d", n, inEffect, len(s.rewrites))
	}
	_ = s.Revert(ctx)
	if fmt.Sprint(f.keys[serviceDNS(eth)]) != "map[ServerAddresses:[192.168.88.1]]" {
		t.Fatalf("restored %v", f.keys[serviceDNS(eth)])
	}
}
