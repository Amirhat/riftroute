package netmon

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider"
)

// Poller detects network changes by diffing successive provider snapshots and
// emits the corresponding events. It is provider-agnostic, so it drives
// auto-apply identically on macOS, Linux, and the fake backend.
type Poller struct {
	prov     provider.RouteProvider
	interval time.Duration
	out      chan Event
	last     *snapshot
	now      func() time.Time
}

type snapshot struct {
	vpnUp     []string
	vpnOn     bool
	defaultV4 string // "gw|iface|owner"
	defaultV6 string
	dns       string
	ifaces    string
}

// NewPoller builds a poller over a provider with the given poll interval.
func NewPoller(prov provider.RouteProvider, interval time.Duration) *Poller {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &Poller{prov: prov, interval: interval, out: make(chan Event, 64), now: time.Now}
}

func (p *Poller) Events() <-chan Event { return p.out }

// Run polls until ctx is canceled.
func (p *Poller) Run(ctx context.Context) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	p.PollOnce(ctx) // prime baseline (emits nothing on first call)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.PollOnce(ctx)
		}
	}
}

// PollOnce captures a snapshot, diffs it against the previous one, emits any
// resulting events, and returns them (the return value aids testing). The first
// call only establishes the baseline.
func (p *Poller) PollOnce(ctx context.Context) []Event {
	prev := p.last
	cur := p.capture(ctx, prev)
	p.last = cur
	if prev == nil {
		return nil // baseline
	}

	var events []Event
	add := func(t EventType, iface, detail string) {
		ev := Event{Type: t, Iface: iface, Detail: detail, TS: p.now()}
		events = append(events, ev)
		select {
		case p.out <- ev:
		default:
		}
	}

	switch {
	case !prev.vpnOn && cur.vpnOn:
		add(EventVPNUp, strings.Join(cur.vpnUp, ","), "tunnel came up")
	case prev.vpnOn && !cur.vpnOn:
		add(EventVPNDown, strings.Join(prev.vpnUp, ","), "tunnel went down")
	}
	if prev.defaultV4 != cur.defaultV4 {
		add(EventDefaultRouteChanged, "", "v4 default: "+cur.defaultV4)
	}
	if prev.defaultV6 != cur.defaultV6 {
		add(EventDefaultRouteChanged, "", "v6 default: "+cur.defaultV6)
	}
	if prev.dns != cur.dns {
		add(EventDNSChanged, "", cur.dns)
	}
	if prev.ifaces != cur.ifaces {
		add(EventLinkChanged, "", "interface set changed")
	}
	return events
}

// capture builds a fresh snapshot. When a provider read FAILS for a field, it
// carries the previous snapshot's value forward instead of recording an empty
// value — otherwise a transient read error looks identical to a real state
// change and fires a spurious event → a needless (and potentially unsafe)
// reconcile during network turbulence.
func (p *Poller) capture(ctx context.Context, prev *snapshot) *snapshot {
	s := &snapshot{}
	if ifaces, err := p.prov.Interfaces(ctx); err == nil {
		var ifNames []string
		for _, ifc := range ifaces {
			state := "down"
			if ifc.Up {
				state = "up"
			}
			ifNames = append(ifNames, ifc.Name+":"+state)
			if ifc.IsVPN && ifc.Up {
				s.vpnOn = true
				s.vpnUp = append(s.vpnUp, ifc.Name)
			}
		}
		sort.Strings(s.vpnUp)
		sort.Strings(ifNames)
		s.ifaces = strings.Join(ifNames, ",")
	} else if prev != nil {
		s.vpnOn, s.vpnUp, s.ifaces = prev.vpnOn, prev.vpnUp, prev.ifaces
	}
	s.defaultV4 = defaultKey(ctx, p.prov, domain.FamilyV4, prevOr(prev, func(x *snapshot) string { return x.defaultV4 }))
	s.defaultV6 = defaultKey(ctx, p.prov, domain.FamilyV6, prevOr(prev, func(x *snapshot) string { return x.defaultV6 }))
	if dns, err := p.prov.DNSConfig(ctx); err == nil {
		s.dns = strings.Join(dns.Servers, ",")
	} else if prev != nil {
		s.dns = prev.dns
	}
	return s
}

func prevOr(prev *snapshot, get func(*snapshot) string) string {
	if prev == nil {
		return ""
	}
	return get(prev)
}

// defaultKey returns "gw|iface|owner" for the default route in fam. On a provider
// read error it returns prevVal (carry-forward), NOT "" — so a transient failure
// is not mistaken for "the default route disappeared".
func defaultKey(ctx context.Context, prov provider.RouteProvider, fam domain.Family, prevVal string) string {
	def := "0.0.0.0/0"
	if fam == domain.FamilyV6 {
		def = "::/0"
	}
	routes, err := prov.ListRoutes(ctx, fam)
	if err != nil {
		return prevVal // read failed → keep prior value, don't fire a false change
	}
	for _, r := range routes {
		if r.DstCIDR == def {
			return r.Gateway + "|" + r.Iface + "|" + string(r.Owner)
		}
	}
	return ""
}
