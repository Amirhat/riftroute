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
	physV4    string // the physical defaults' next hops (defaultKeys)
	physV6    string
	dns       string
	ifaces    string
	// tsExit is Tailscale's default routes on Linux (its exit node), kept in
	// its own table: turned on or off, nothing in the main table changes.
	tsExit string
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
	if prev.physV4 != cur.physV4 {
		add(EventPhysicalGatewayChanged, "", "v4 physical gateway: "+cur.physV4)
	}
	if prev.physV6 != cur.physV6 {
		add(EventPhysicalGatewayChanged, "", "v6 physical gateway: "+cur.physV6)
	}
	if prev.dns != cur.dns {
		add(EventDNSChanged, "", cur.dns)
	}
	if prev.ifaces != cur.ifaces {
		add(EventLinkChanged, "", "interface set changed")
	}
	if prev.tsExit != cur.tsExit {
		add(EventDefaultRouteChanged, "", "Tailscale's exit node: "+orNone(cur.tsExit))
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
	s.defaultV4, s.physV4 = defaultKeys(ctx, p.prov, domain.FamilyV4,
		prevOr(prev, func(x *snapshot) string { return x.defaultV4 }), prevOr(prev, func(x *snapshot) string { return x.physV4 }))
	s.defaultV6, s.physV6 = defaultKeys(ctx, p.prov, domain.FamilyV6,
		prevOr(prev, func(x *snapshot) string { return x.defaultV6 }), prevOr(prev, func(x *snapshot) string { return x.physV6 }))
	if dns, err := p.prov.DNSConfig(ctx); err == nil {
		s.dns = strings.Join(dns.Servers, ",")
	} else if prev != nil {
		s.dns = prev.dns
	}
	s.tsExit = p.tailscaleExit(ctx, s.ifaces, prevOr(prev, func(x *snapshot) string { return x.tsExit }))
	return s
}

// tableLister reads a routing table beside main (Linux: Tailscale's).
type tableLister interface {
	ListTable(ctx context.Context, family domain.Family, table string) ([]domain.Route, error)
}

// tailscaleExit is Tailscale's default routes in its table ("" without
// them, or without Tailscale); prevVal on a read error.
func (p *Poller) tailscaleExit(ctx context.Context, ifaces, prevVal string) string {
	tl, ok := p.prov.(tableLister)
	if !ok || !strings.Contains(ifaces, "tailscale") {
		return ""
	}
	var out []string
	for _, fam := range []domain.Family{domain.FamilyV4, domain.FamilyV6} {
		rs, err := tl.ListTable(ctx, fam, "52")
		if err != nil {
			return prevVal
		}
		for _, r := range rs {
			if r.DstCIDR == "0.0.0.0/0" || r.DstCIDR == "::/0" {
				out = append(out, r.DstCIDR+"|"+r.Iface)
			}
		}
	}
	return strings.Join(out, ",")
}

func orNone(s string) string {
	if s == "" {
		return "off"
	}
	return s
}

func prevOr(prev *snapshot, get func(*snapshot) string) string {
	if prev == nil {
		return ""
	}
	return get(prev)
}

// defaultKeys returns, for fam, "gw|iface|owner" for the default route (the
// first the table lists), and the physical defaults' next hops ("gw|iface",
// sorted). With a VPN's default winning, the physical one can change — a new
// Wi-Fi network with the same addressing, Ethernet plugged in beside it —
// while the winning one doesn't, and the exclude routes' next hop must
// follow. On a provider read error both carry forward (prevDef, prevPhys),
// NOT "" — so a transient failure is not mistaken for "the default route
// disappeared".
func defaultKeys(ctx context.Context, prov provider.RouteProvider, fam domain.Family, prevDef, prevPhys string) (def, phys string) {
	routes, err := prov.ListRoutes(ctx, fam)
	if err != nil {
		return prevDef, prevPhys // read failed → keep prior values, don't fire a false change
	}
	return defaultKeysFrom(routes, fam)
}

// defaultKeysFrom is defaultKeys over a table read.
func defaultKeysFrom(routes []domain.Route, fam domain.Family) (def, phys string) {
	want := "0.0.0.0/0"
	if fam == domain.FamilyV6 {
		want = "::/0"
	}
	var hops []string
	for _, r := range routes {
		if r.DstCIDR != want || r.Table != "" {
			continue
		}
		if def == "" {
			def = r.Gateway + "|" + r.Iface + "|" + string(r.Owner)
		}
		if r.Gateway != "" && r.Owner != domain.OwnerVPN && r.Owner != domain.OwnerRiftRoute {
			hops = append(hops, r.Gateway+"|"+r.Iface)
		}
	}
	sort.Strings(hops)
	return def, strings.Join(hops, ",")
}
