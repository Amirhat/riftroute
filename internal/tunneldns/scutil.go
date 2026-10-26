package tunneldns

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// macOS: the primary service's DNS, swapped and restored (docs/tunnels-full.md,
// "macOS: the primary service's DNS, swapped and restored"). A resolver of
// RiftRoute's own "for every domain" ranks behind the primary service's
// whatever order it's given; replacing the primary service's ServerAddresses
// makes the tunnel's the default resolver, and touches no route.
//
// What's changed is recorded in the dynamic store, where it outlives a
// crashed daemon (until a reboot, which also undoes the swap):
//   - backupPrefix<service>: the service's DNS dictionary before the swap (or
//     a marker that it had none);
//   - appliedKey: the servers RiftRoute wrote, so a restore only puts the
//     backup back while they're still there — a value the service's owner
//     wrote since (a DHCP renewal, a VPN reconnecting) is theirs.
const (
	backupPrefix = "State:/Network/RiftRoute/DNSBackup/"
	appliedKey   = "State:/Network/RiftRoute/DNSApplied"
	globalIPv4   = "State:/Network/Global/IPv4"
	absentMarker = "RiftRouteAbsent"
)

// recheckEvery is how often, while a swap is in place, the primary service
// and its DNS are checked: its owner rewrites it, and the primary changes
// (Wi-Fi to Ethernet, the main VPN up or down).
var recheckEvery = 5 * time.Second

// An owner that rewrites the service's DNS maxRewrites times in
// rewriteWindow is let have it: held against it, the DNS would flip back
// to the owner's for seconds at a time, with a cache flush each time.
const (
	maxRewrites   = 5
	rewriteWindow = 10 * time.Minute
)

// runner runs a command with stdin and returns its standard output.
type runner func(ctx context.Context, stdin string, name string, args ...string) (string, error)

// reService is a service ID as the dynamic store names it (a UUID, or a
// name some VPN client picks), and reWord one value of an array put back
// as it was read: nothing a script could be bent with.
var (
	reService = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	reWord    = regexp.MustCompile(`^[A-Za-z0-9._:%-]{1,253}$`)
)

type scutilApplier struct {
	run runner
	log Logf
	now func() time.Time

	mu      sync.Mutex
	applied Config // what's in place, empty when nothing is
	service string // the primary service it's applied to
	stop    chan struct{}
	// rewrites are the owner's rewrites of the service's DNS while it's
	// held; note, why it's let go (held false).
	rewrites []time.Time
	held     bool
	note     noteBox
}

func newScutil(run runner, log Logf) *scutilApplier {
	return &scutilApplier{run: run, log: log, now: time.Now}
}

func (s *scutilApplier) Backend() string { return "macOS primary service DNS (swapped)" }

// Note says when the swap was let go, its owner rewriting it.
func (s *scutilApplier) Note() string { return s.note.get() }

func (s *scutilApplier) scutil(ctx context.Context, script string) (string, error) {
	return s.run(ctx, "open\n"+script+"close\n", "scutil")
}

// show returns a key's dictionary as scutil prints it, or "" without one.
func (s *scutilApplier) show(ctx context.Context, key string) string {
	out, err := s.run(ctx, "show "+key+"\n", "scutil")
	if err != nil || strings.Contains(out, "No such key") {
		return ""
	}
	return out
}

// primary is the primary service's ID, or "".
func (s *scutilApplier) primary(ctx context.Context) string {
	for _, l := range strings.Split(s.show(ctx, globalIPv4), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), " : "); ok && k == "PrimaryService" && reService.MatchString(v) {
			return v
		}
	}
	return ""
}

// arrayValues reads an array's values from scutil's dictionary output.
func arrayValues(dict, key string) []string {
	var out []string
	in := false
	for _, l := range strings.Split(dict, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case !in && strings.HasPrefix(t, key+" : <array> {"):
			in = true
		case in && t == "}":
			return out
		case in:
			if _, v, ok := strings.Cut(t, " : "); ok {
				out = append(out, v)
			}
		}
	}
	return out
}

func serviceDNS(service string) string { return "State:/Network/Service/" + service + "/DNS" }

// Apply makes cfg's servers the default resolver: the primary service's
// ServerAddresses (and SearchDomains, with search domains), backed up first.
func (s *scutilApplier) Apply(ctx context.Context, cfg Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg.Empty() {
		return s.revertLocked(ctx)
	}
	svc := s.primary(ctx)
	if svc == "" {
		return fmt.Errorf("macOS has no primary network service to give the tunnel's DNS to")
	}
	if s.service != "" && s.service != svc {
		s.restoreLocked(ctx, s.service) // the primary moved on
	}
	if err := s.swapLocked(ctx, svc, cfg); err != nil {
		return err
	}
	s.applied, s.service = cfg, svc
	s.rewrites, s.held = nil, true
	s.note.set("")
	if s.stop == nil {
		s.stop = make(chan struct{})
		go s.watch(s.stop)
	}
	return nil
}

// swapLocked backs the service's DNS up (once) and writes cfg into it.
func (s *scutilApplier) swapLocked(ctx context.Context, svc string, cfg Config) error {
	if s.show(ctx, backupPrefix+svc) == "" {
		script := "get " + serviceDNS(svc) + "\nset " + backupPrefix + svc + "\n"
		if s.show(ctx, serviceDNS(svc)) == "" {
			script = "d.init\nd.add " + absentMarker + " # 1\nset " + backupPrefix + svc + "\n"
		}
		if _, err := s.scutil(ctx, script); err != nil {
			return fmt.Errorf("back up the DNS of %s: %w", svc, err)
		}
	}
	servers := addrStrings(cfg.Servers)
	script := "get " + serviceDNS(svc) + "\nd.add ServerAddresses * " + strings.Join(servers, " ") + "\n"
	if len(cfg.Search) > 0 {
		script += "d.add SearchDomains * " + strings.Join(cfg.Search, " ") + "\n"
	}
	script += "set " + serviceDNS(svc) + "\n" +
		"d.init\nd.add ServerAddresses * " + strings.Join(servers, " ") + "\nd.add Service " + svc + "\n"
	if len(cfg.Search) > 0 {
		script += "d.add Search # 1\n" // its SearchDomains are ours too: a restore puts them back
	}
	script += "set " + appliedKey + "\n"
	if _, err := s.scutil(ctx, script); err != nil {
		return fmt.Errorf("set the DNS of %s: %w", svc, err)
	}
	s.flush(ctx)
	return nil
}

// restoreLocked puts a service's backup back while it still holds the
// servers RiftRoute wrote, and drops the backup either way.
func (s *scutilApplier) restoreLocked(ctx context.Context, svc string) {
	applied := s.show(ctx, appliedKey)
	ours := arrayValues(applied, "ServerAddresses")
	now := arrayValues(s.show(ctx, serviceDNS(svc)), "ServerAddresses")
	backup := s.show(ctx, backupPrefix+svc)
	script := ""
	switch {
	case backup == "":
	case len(ours) == 0 || !slices.Equal(now, ours):
		// Its owner wrote it since: theirs, left as it is.
	case strings.Contains(backup, absentMarker):
		script = "remove " + serviceDNS(svc) + "\n"
	default:
		script = restoreScript(svc, backup, strings.Contains(applied, "Search : 1"))
	}
	_, _ = s.scutil(ctx, script+"remove "+backupPrefix+svc+"\n")
}

// restoreScript puts what the swap changed back from the backup — the
// servers, and the search domains when it set some — into the service's
// DNS as it is now, so whatever else its owner changed meanwhile stays.
// The whole backup goes back when a value isn't plainly an address or a
// name, which a script couldn't carry.
func restoreScript(svc, backup string, search bool) string {
	servers, domains := arrayValues(backup, "ServerAddresses"), arrayValues(backup, "SearchDomains")
	for _, v := range slices.Concat(servers, domains) {
		if !reWord.MatchString(v) {
			return "get " + backupPrefix + svc + "\nset " + serviceDNS(svc) + "\n"
		}
	}
	script := "get " + serviceDNS(svc) + "\n"
	if len(servers) > 0 {
		script += "d.add ServerAddresses * " + strings.Join(servers, " ") + "\n"
	} else {
		script += "d.remove ServerAddresses\n"
	}
	switch {
	case !search:
	case len(domains) > 0:
		script += "d.add SearchDomains * " + strings.Join(domains, " ") + "\n"
	default:
		script += "d.remove SearchDomains\n"
	}
	return script + "set " + serviceDNS(svc) + "\n"
}

// Revert puts back whatever is swapped.
func (s *scutilApplier) Revert(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revertLocked(ctx)
}

func (s *scutilApplier) revertLocked(ctx context.Context) error {
	if s.stop != nil {
		close(s.stop)
		s.stop = nil
	}
	s.recoverLocked(ctx)
	s.applied, s.service = Config{}, ""
	s.rewrites, s.held = nil, false
	s.note.set("")
	return nil
}

// Recover undoes what a run that didn't end cleanly left: every backup goes
// back while its service still holds RiftRoute's servers.
func (s *scutilApplier) Recover(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recoverLocked(ctx)
	return nil
}

func (s *scutilApplier) recoverLocked(ctx context.Context) {
	out, _ := s.run(ctx, "list "+backupPrefix+".*\n", "scutil")
	restored := false
	for _, l := range strings.Split(out, "\n") {
		if i := strings.Index(l, backupPrefix); i >= 0 {
			if svc := strings.TrimSpace(l[i+len(backupPrefix):]); reService.MatchString(svc) {
				s.restoreLocked(ctx, svc)
				restored = true
			}
		}
	}
	_, _ = s.scutil(ctx, "remove "+appliedKey+"\n")
	if restored {
		s.flush(ctx)
	}
}

// watch rechecks the swap while it's in place.
func (s *scutilApplier) watch(stop chan struct{}) {
	t := time.NewTicker(recheckEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			s.recheck(ctx)
			cancel()
		}
	}
}

// recheck applies the swap again where it's gone: the primary service
// changed (restore the old one, swap the new), or its owner rewrote its DNS
// (that's its value now: back it up again, and swap — unless it keeps
// doing so: maxRewrites).
func (s *scutilApplier) recheck(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applied.Empty() || !s.held {
		return
	}
	svc := s.primary(ctx)
	switch {
	case svc == "":
		return // between networks: the next check sees where it lands
	case svc != s.service:
		s.restoreLocked(ctx, s.service)
	case slices.Equal(arrayValues(s.show(ctx, serviceDNS(svc)), "ServerAddresses"), addrStrings(s.applied.Servers)):
		return
	default:
		now := s.now()
		s.rewrites = append(slices.DeleteFunc(s.rewrites, func(t time.Time) bool { return now.Sub(t) > rewriteWindow }), now)
		iface := scalarValue(s.show(ctx, serviceDNS(svc)), "InterfaceName")
		s.logf("the network service's own DNS was written again; the tunnel's goes back in", "service", svc, "iface", iface, "times", len(s.rewrites))
		// The owner's new value is the backup now (or, let go, simply its).
		script := "remove " + backupPrefix + svc + "\n"
		if len(s.rewrites) >= maxRewrites {
			s.held = false
			s.note.set(fmt.Sprintf("the network service%s keeps rewriting its DNS (%d times in %d minutes), so RiftRoute stopped putting "+
				"the tunnel's back: your system's own DNS is in use", onIface(iface), len(s.rewrites), int(rewriteWindow/time.Minute)))
			s.logf("letting the network service keep its DNS", "service", svc, "iface", iface)
			_, _ = s.scutil(ctx, script+"remove "+appliedKey+"\n")
			s.flush(ctx)
			return
		}
		_, _ = s.scutil(ctx, script)
	}
	if err := s.swapLocked(ctx, svc, s.applied); err == nil {
		s.service = svc
	}
}

func (s *scutilApplier) logf(msg string, args ...any) {
	if s.log != nil {
		s.log(msg, args...)
	}
}

func onIface(iface string) string {
	if iface == "" {
		return ""
	}
	return " on " + iface
}

// scalarValue reads a scalar's value from scutil's dictionary output.
func scalarValue(dict, key string) string {
	for _, l := range strings.Split(dict, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), " : "); ok && k == key && !strings.HasPrefix(v, "<") {
			return v
		}
	}
	return ""
}

// flush drops the resolver's caches, so the change is seen at once.
func (s *scutilApplier) flush(ctx context.Context) {
	_, _ = s.run(ctx, "", "dscacheutil", "-flushcache")
	_, _ = s.run(ctx, "", "killall", "-HUP", "mDNSResponder")
}

func addrStrings(as []netip.Addr) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out
}
