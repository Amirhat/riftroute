package tunneldns

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Amirhat/riftroute/internal/dnsproxy"
)

// macOS: a resolver of RiftRoute's own for every domain, at a forwarder on
// loopback that asks the tunnel's DNS servers through the tunnel
// (docs/tunnels-full.md, "macOS: a resolver of our own, at a forwarder").
//
// Not the primary service's DNS, swapped (the first design): mDNSResponder
// sends the primary service's queries bound to that service's interface, and
// beside an NE VPN that takes DNS for every domain, the system steers the
// resolver's queries into the VPN's tunnel whatever the routes say. The
// owner's Mac showed both (2026-10-26, diagnostics 2–4): the tunnel's server
// was never asked. A process's own queries follow the routes, and loopback
// isn't steered. So the system asks the forwarder (riftrouted, dnsproxy),
// and the forwarder asks the tunnel's servers, whose host routes go into
// the tunnel. The primary service's DNS is never touched.
//
// Another service that also takes every domain (an NE VPN's matchDomains "")
// would rank ahead of ours: while ours is in place, its claim is set aside
// (SupplementalMatchDomains/Orders removed from its State: DNS), and put
// back after.
//
// What's changed is in the dynamic store, where it outlives a crashed daemon
// (until a reboot, which undoes it too):
//   - ourKey: our resolver;
//   - backupPrefix<service>: a service's DNS before its claim was set aside;
//   - appliedKey: the forwarder's port, a record that the resolver is
//     RiftRoute's.
const (
	ourService   = "RiftRoute-TunnelDNS"
	backupPrefix = "State:/Network/RiftRoute/DNSBackup/"
	appliedKey   = "State:/Network/RiftRoute/DNSApplied"
)

var ourKey = serviceDNS(ourService)

// recheckEvery is how often, while ours is in place, the services are looked
// at again: an NE VPN that reconnects takes every domain again. After a
// write fails, the next waits quietAfterFailure.
var recheckEvery, quietAfterFailure = 5 * time.Second, 30 * time.Second

// A service that takes every domain back maxRewrites times in rewriteWindow
// is let have it: set aside again and again, DNS would flip between its
// resolver and ours, with a cache flush each time.
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
	log *slog.Logger
	now func() time.Time
	// upstreamPort is the port the tunnel's servers are asked on (tests).
	upstreamPort int

	mu      sync.Mutex
	applied Config // what's in place, empty when nothing is
	fwd     *dnsproxy.Proxy
	stop    chan struct{}
	// rewrites are the times another service took every domain back while
	// ours was held; note, why it was let go (held false).
	rewrites []time.Time
	held     bool
	note     noteBox
	// quietUntil: a recheck whose writes failed (configd not answering)
	// waits this long before writing again — no flush every few seconds.
	quietUntil time.Time
}

func newScutil(run runner, log *slog.Logger) *scutilApplier {
	if log == nil {
		log = slog.Default()
	}
	return &scutilApplier{run: timed(run, log), log: log, now: time.Now, upstreamPort: 53}
}

// timed logs a tool's run that's slow or fails, with the first line of
// what it was given: after a crash, Recover once waited out its whole time
// on a hung one.
func timed(run runner, log *slog.Logger) runner {
	return func(ctx context.Context, stdin, name string, args ...string) (string, error) {
		start := time.Now()
		out, err := run(ctx, stdin, name, args...)
		if took := time.Since(start); took > 2*time.Second || err != nil && ctx.Err() == nil && name == "scutil" {
			first, _, _ := strings.Cut(strings.TrimPrefix(stdin, "open\n"), "\n")
			log.Warn("a system tool was slow or failed", "tool", name, "first", first, "took", took.Round(time.Millisecond), "err", err)
		}
		return out, err
	}
}

func (s *scutilApplier) Backend() string {
	return "macOS resolver for every domain, at a forwarder on loopback"
}

// Note says when ours was let go, another service taking every domain back:
// then it's no longer in effect.
func (s *scutilApplier) Note() (string, bool) {
	n := s.note.get()
	return n, n == ""
}

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
			} else if strings.HasSuffix(t, " :") { // an empty string
				out = append(out, "")
			}
		}
	}
	return out
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

func serviceDNS(service string) string { return "State:/Network/Service/" + service + "/DNS" }

// takesEveryDomain reports whether a service's DNS claims every domain:
// SupplementalMatchDomains holds "".
func takesEveryDomain(dict string) bool {
	return strings.Contains(dict, "SupplementalMatchDomains : ") && slices.Contains(arrayValues(dict, "SupplementalMatchDomains"), "")
}

// Apply makes cfg's servers the system's DNS for every domain: the
// forwarder asks them, our resolver points at the forwarder, and any other
// service's claim on every domain is set aside.
func (s *scutilApplier) Apply(ctx context.Context, cfg Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg.Empty() {
		return s.revertLocked(ctx)
	}
	for _, d := range cfg.Search {
		if !reWord.MatchString(d) {
			return fmt.Errorf("bad search domain %q", d)
		}
	}
	if s.fwd == nil {
		s.fwd = dnsproxy.New(s.log, nil).Named("full tunnel's DNS forwarder")
	}
	ups := make([]string, len(cfg.Servers))
	for i, a := range cfg.Servers {
		ups[i] = netip.AddrPortFrom(a, uint16(s.upstreamPort)).String()
	}
	s.fwd.SetUpstreams(ups)
	port, err := s.fwd.Start()
	if err != nil {
		return fmt.Errorf("start the DNS forwarder: %w", err)
	}
	if err := s.putLocked(ctx, port, cfg); err != nil {
		return err
	}
	s.setAsideLocked(ctx)
	s.applied = cfg
	s.rewrites, s.held = nil, true
	s.note.set("")
	s.flush(ctx)
	if s.stop == nil {
		s.stop = make(chan struct{})
		go s.watch(s.stop)
	}
	return nil
}

// putLocked writes our resolver, and the record that it's ours.
func (s *scutilApplier) putLocked(ctx context.Context, port int, cfg Config) error {
	script := "d.init\nd.add ServerAddresses * 127.0.0.1\nd.add ServerPort # " + strconv.Itoa(port) + "\n" +
		"d.add SupplementalMatchDomains * \"\"\n"
	if len(cfg.Search) > 0 {
		script += "d.add SearchDomains * " + strings.Join(cfg.Search, " ") + "\n"
	}
	script += "set " + ourKey + "\nd.init\nd.add Port # " + strconv.Itoa(port) + "\nset " + appliedKey + "\n"
	if _, err := s.scutil(ctx, script); err != nil {
		return fmt.Errorf("add the tunnel's resolver: %w", err)
	}
	return nil
}

// ours reports whether our resolver is in place, at the forwarder.
func (s *scutilApplier) ours(ctx context.Context, port int) bool {
	d := s.show(ctx, ourKey)
	return port != 0 && scalarValue(d, "ServerPort") == strconv.Itoa(port) && takesEveryDomain(d)
}

// claimants are the other services that take every domain.
func (s *scutilApplier) claimants(ctx context.Context) []string {
	out, _ := s.run(ctx, "list State:/Network/Service/[^/]+/DNS\n", "scutil")
	var svcs []string
	for _, l := range strings.Split(out, "\n") {
		i := strings.Index(l, "State:/Network/Service/")
		if i < 0 {
			continue
		}
		svc := strings.TrimSuffix(strings.TrimSpace(l[i+len("State:/Network/Service/"):]), "/DNS")
		if svc == ourService || !reService.MatchString(svc) {
			continue
		}
		if takesEveryDomain(s.show(ctx, serviceDNS(svc))) {
			svcs = append(svcs, svc)
		}
	}
	return svcs
}

// setAsideLocked backs each claimant's DNS up (once) and removes its claim
// on every domain: its match domains and their orders when "" is alone,
// "" alone when other domains are beside it. One it can't take apart
// cleanly (orders beside other domains, a value a script can't carry) is
// left, and logged.
func (s *scutilApplier) setAsideLocked(ctx context.Context) {
	for _, svc := range s.claimants(ctx) {
		dict := s.show(ctx, serviceDNS(svc))
		others := slices.DeleteFunc(arrayValues(dict, "SupplementalMatchDomains"), func(v string) bool { return v == "" })
		var script string
		switch {
		case len(others) == 0:
			script = "d.remove SupplementalMatchDomains\nd.remove SupplementalMatchOrders\n"
		case strings.Contains(dict, "SupplementalMatchOrders : ") || slices.ContainsFunc(others, func(v string) bool { return !reWord.MatchString(v) }):
			s.log.Warn("a network service takes every domain beside others; left as it is, so it may outrank the tunnel's DNS", "service", svc)
			continue
		default:
			script = "d.add SupplementalMatchDomains * " + strings.Join(others, " ") + "\n"
		}
		if s.show(ctx, backupPrefix+svc) == "" {
			if _, err := s.scutil(ctx, "get "+serviceDNS(svc)+"\nset "+backupPrefix+svc+"\n"); err != nil {
				continue
			}
		}
		_, _ = s.scutil(ctx, "get "+serviceDNS(svc)+"\n"+script+"set "+serviceDNS(svc)+"\n")
	}
}

// restoreLocked puts a set-aside service's claim back while it's still set
// aside, and drops the backup either way: one that took every domain back
// since, or went, is left as it is.
func (s *scutilApplier) restoreLocked(ctx context.Context, svc string) {
	backup := s.show(ctx, backupPrefix+svc)
	now := s.show(ctx, serviceDNS(svc))
	script := ""
	switch {
	case backup == "", now == "", takesEveryDomain(now):
	case strings.Contains(backup, "SupplementalMatchOrders : "):
		// Orders are numbers, which a script's array can't carry: the whole
		// dictionary, while its servers are as they were.
		if slices.Equal(arrayValues(now, "ServerAddresses"), arrayValues(backup, "ServerAddresses")) {
			script = "get " + backupPrefix + svc + "\nset " + serviceDNS(svc) + "\n"
		}
	default:
		match := arrayValues(backup, "SupplementalMatchDomains")
		quoted := make([]string, 0, len(match))
		for _, v := range match {
			if v != "" && !reWord.MatchString(v) {
				quoted = nil
				break
			}
			quoted = append(quoted, cmp.Or(v, `""`))
		}
		if len(quoted) > 0 {
			script = "get " + serviceDNS(svc) + "\nd.add SupplementalMatchDomains * " + strings.Join(quoted, " ") + "\nset " + serviceDNS(svc) + "\n"
		}
	}
	_, _ = s.scutil(ctx, script+"remove "+backupPrefix+svc+"\n")
}

// Revert puts back whatever was changed, and stops the forwarder.
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
	if s.fwd != nil {
		s.fwd.Stop()
	}
	s.applied = Config{}
	s.rewrites, s.held = nil, false
	s.note.set("")
	return s.leftLocked(ctx)
}

// Recover undoes what a run that didn't end cleanly left: our resolver goes
// (its forwarder went with that run), and every service set aside gets its
// claim back. An error says something was left (the manager tries again).
func (s *scutilApplier) Recover(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recoverLocked(ctx)
	return s.leftLocked(ctx)
}

// leftLocked says what of RiftRoute's is still in the store, or nil.
func (s *scutilApplier) leftLocked(ctx context.Context) error {
	if s.show(ctx, ourKey) != "" {
		return fmt.Errorf("RiftRoute's resolver is still in place")
	}
	if out, _ := s.run(ctx, "list "+backupPrefix+".*\n", "scutil"); strings.Contains(out, backupPrefix) {
		return fmt.Errorf("a network service's DNS is still set aside")
	}
	return nil
}

func (s *scutilApplier) recoverLocked(ctx context.Context) {
	changed := s.show(ctx, ourKey) != ""
	_, _ = s.scutil(ctx, "remove "+ourKey+"\n")
	out, _ := s.run(ctx, "list "+backupPrefix+".*\n", "scutil")
	for _, l := range strings.Split(out, "\n") {
		if i := strings.Index(l, backupPrefix); i >= 0 {
			if svc := strings.TrimSpace(l[i+len(backupPrefix):]); reService.MatchString(svc) {
				s.restoreLocked(ctx, svc)
				changed = true
			}
		}
	}
	_, _ = s.scutil(ctx, "remove "+appliedKey+"\n")
	if changed {
		s.flush(ctx)
	}
}

// watch rechecks ours while it's in place.
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

// recheck puts ours back if it's gone, and sets aside a service that took
// every domain back (an NE VPN reconnecting) — unless one keeps doing so
// (maxRewrites), when it's let have it.
func (s *scutilApplier) recheck(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applied.Empty() || !s.held || s.now().Before(s.quietUntil) {
		return
	}
	if _, port := s.fwd.Active(); !s.ours(ctx, port) {
		if err := s.putLocked(ctx, port, s.applied); err != nil {
			s.quietUntil = s.now().Add(quietAfterFailure)
			return
		}
		s.flush(ctx)
	}
	back := s.claimants(ctx)
	if len(back) == 0 {
		return
	}
	now := s.now()
	s.rewrites = append(slices.DeleteFunc(s.rewrites, func(t time.Time) bool { return now.Sub(t) > rewriteWindow }), now)
	s.log.Info("a network service took DNS for every domain back; set aside again", "services", strings.Join(back, ","), "times", len(s.rewrites))
	if len(s.rewrites) >= maxRewrites {
		s.held = false
		s.note.set(fmt.Sprintf("another network service keeps taking DNS for every domain back (%d times in %d minutes), so RiftRoute "+
			"stopped setting it aside: your system's own DNS is in use", len(s.rewrites), int(rewriteWindow/time.Minute)))
		s.log.Info("letting the network service keep DNS for every domain", "services", strings.Join(back, ","))
		s.recoverLocked(ctx)
		return
	}
	for _, svc := range back { // its new DNS is the backup now
		_, _ = s.scutil(ctx, "remove "+backupPrefix+svc+"\n")
	}
	s.setAsideLocked(ctx)
	s.flush(ctx)
}

// flush drops the resolver's caches, so the change is seen at once.
func (s *scutilApplier) flush(ctx context.Context) {
	_, _ = s.run(ctx, "", "dscacheutil", "-flushcache")
	_, _ = s.run(ctx, "", "killall", "-HUP", "mDNSResponder")
}
