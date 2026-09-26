package reconcile_test

import (
	"context"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/dns"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/routing"
	"github.com/Amirhat/riftroute/internal/safety"
)

// Connecting a tunnel whose network an installed include rule covers: the
// rule is matched before the routing table and would capture the tunnel's
// traffic into the VPN. The tunnel apply cuts the rule around the tunnel's
// network — with auto-apply off too — and leaves the app rule alone.
func TestTunnelConnectCutsIncludeRulesAroundItsNetwork(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	for _, sel := range []string{"to 10.0.0.0/8", "from all fwmark " + routing.ModelBMark} {
		if err := h.prov.AddRule(ctx, domain.ManagedRule{PolicyRule: domain.PolicyRule{
			Priority: routing.ModelBRulePrio, Selector: sel, Table: routing.ModelBTable, Family: domain.FamilyV4, Proto: "riftroute",
		}}); err != nil {
			t.Fatal(err)
		}
	}
	h.setTunnels(routing.TunnelInput{Name: "infra", Iface: "utun9", Routes: []string{"10.70.0.0/16"}})
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}

	rules, err := h.prov.ListRules(ctx, domain.FamilyV4)
	if err != nil {
		t.Fatal(err)
	}
	tunnelNet := netip.MustParsePrefix("10.70.0.0/16")
	var dests, apps int
	for _, r := range rules {
		if r.Proto != "riftroute" {
			continue
		}
		dst, ok := strings.CutPrefix(r.Selector, "to ")
		if !ok {
			apps++
			continue
		}
		dests++
		if netip.MustParsePrefix(dst).Overlaps(tunnelNet) {
			t.Errorf("include rule %q still captures the tunnel's network", r.Selector)
		}
	}
	if dests != 8 || apps != 1 {
		t.Errorf("%d destination rule(s), %d app rule(s): %+v", dests, apps, rules)
	}
	if got := h.kernel(t)["10.70.0.0/16"]; len(got) != 1 || got[0] != "utun9" {
		t.Errorf("tunnel route = %v", got)
	}
}

// With auto-apply off, what a tunnel took comes back when it goes: the
// include rule it cut and the exclude route inside its network return on the
// disconnect's tunnel apply — no full apply is coming to do it, and without
// them that traffic would leave outside the VPN.
func TestTunnelDisconnectRestoresWhatItsConnectCut(t *testing.T) {
	h := newTunnelHarness(t) // auto-apply off
	ctx := context.Background()
	if err := h.prov.AddRule(ctx, domain.ManagedRule{PolicyRule: domain.PolicyRule{
		Priority: routing.ModelBRulePrio, Selector: "to 10.0.0.0/8", Table: routing.ModelBTable, Family: domain.FamilyV4, Proto: "riftroute",
	}}); err != nil {
		t.Fatal(err)
	}
	exclude := domain.ManagedRoute{Route: domain.Route{DstCIDR: "10.70.5.5/32", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4, Owner: domain.OwnerRiftRoute}, ProfileID: "p1"}
	h.own(t, exclude)
	h.profilesBehind(t)

	h.setTunnels(routing.TunnelInput{Name: "infra", Iface: "utun9", Routes: []string{"10.70.0.0/16"}})
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.kernel(t)["10.70.5.5/32"]; len(got) != 0 {
		t.Fatalf("the exclude route didn't yield to the tunnel: %v", got)
	}

	h.setTunnels() // disconnected
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	rules, _ := h.prov.ListRules(ctx, domain.FamilyV4)
	var sels []string
	for _, r := range rules {
		if r.Proto == "riftroute" {
			sels = append(sels, r.Selector)
		}
	}
	if len(sels) != 1 || sels[0] != "to 10.0.0.0/8" {
		t.Errorf("include rules after the disconnect = %q, want the original back", sels)
	}
	if got := h.kernel(t)["10.70.5.5/32"]; len(got) != 1 || got[0] != "en0" {
		t.Errorf("exclude route after the disconnect = %v, want it back via en0", got)
	}
}

// profilesBehind saves the profiles the include rule "to 10.0.0.0/8" and the
// exclude route 10.70.5.5/32 come from: only what a profile still routes is
// put back.
func (h *tunnelHarness) profilesBehind(t *testing.T) {
	t.Helper()
	for _, p := range []domain.Profile{
		{ID: "inc", Name: "inc", Enabled: true, Mode: domain.ModeInclude, Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.0.0.0/8"}}},
		{ID: "p1", Name: "p1", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto", Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.70.5.5/32"}}},
	} {
		if err := h.st.UpsertProfile(p); err != nil {
			t.Fatal(err)
		}
	}
}

// A panic flushes everything; the tunnel apply that follows it must not put
// back what earlier applies had made yield to a tunnel.
func TestPanicForgetsWhatYielded(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	if err := h.prov.AddRule(ctx, domain.ManagedRule{PolicyRule: domain.PolicyRule{
		Priority: routing.ModelBRulePrio, Selector: "to 10.0.0.0/8", Table: routing.ModelBTable, Family: domain.FamilyV4, Proto: "riftroute",
	}}); err != nil {
		t.Fatal(err)
	}
	h.own(t, domain.ManagedRoute{Route: domain.Route{DstCIDR: "10.70.5.5/32", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4, Owner: domain.OwnerRiftRoute}, ProfileID: "p1"})
	h.profilesBehind(t)
	h.setTunnels(routing.TunnelInput{Name: "infra", Iface: "utun9", Routes: []string{"10.70.0.0/16"}})
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	h.setTunnels()
	if err := h.proto.PanicWith(ctx, domain.ActorUI, safety.PanicSteps{Flushing: h.svc.ForgetYielded}); err != nil {
		t.Fatal(err)
	}
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	rules, _ := h.prov.ListRules(ctx, domain.FamilyV4)
	for _, r := range rules {
		if r.Proto == "riftroute" {
			t.Errorf("a flushed rule came back: %q", r.Selector)
		}
	}
	if got := h.kernel(t)["10.70.5.5/32"]; len(got) != 0 {
		t.Errorf("a flushed route came back: %v", got)
	}
}

// Only a change that stands is recorded: a dry run (like a refused or rolled
// back apply) leaves the record alone, so a tunnel disconnect never installs
// what no apply committed.
func TestOnlyACommittedApplyIsRecorded(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	h.setTunnels(routing.TunnelInput{Name: "infra", Iface: "utun9", Routes: []string{"10.70.0.0/16"}})
	if err := h.st.UpsertProfile(domain.Profile{ID: "p1", Name: "p1", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.70.9.0/24"}}}); err != nil {
		t.Fatal(err)
	}
	opts := safety.Options{DryRun: true, Actor: domain.ActorUI}
	if _, err := h.proto.ApplyBuilt(ctx, func(ctx context.Context, _ []domain.ManagedRoute, o *safety.Options) ([]domain.ManagedRoute, []domain.ManagedRule, error) {
		desired, rules, gw, record, err := h.svc.DesiredForApply(ctx)
		o.UseGateway(gw)
		o.OnCommit = record
		return desired, rules, err
	}, opts); err != nil {
		t.Fatal(err)
	}
	h.setTunnels()
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.kernel(t)["10.70.9.0/24"]; len(got) != 0 {
		t.Errorf("a dry run's route was installed: %v", got)
	}
}

// profileP1 saves an exclude profile with a route inside the tunnel's
// network (it yields while the tunnel is up) and one outside it (so an
// apply that enables or disables it has something to change).
func (h *tunnelHarness) profileP1(t *testing.T, enabled bool) {
	t.Helper()
	if err := h.st.UpsertProfile(domain.Profile{ID: "p1", Name: "p1", Enabled: enabled, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.70.9.0/24"}, {Type: domain.RuleCIDR, Value: "10.80.0.0/24"}}}); err != nil {
		t.Fatal(err)
	}
}

// fullApplyOnProbation runs the auto-apply path and returns the transaction
// it leaves on probation (the fake clock holds its guard window open).
func (h *tunnelHarness) fullApplyOnProbation(t *testing.T) string {
	t.Helper()
	h.autoApply.Store(true)
	defer h.autoApply.Store(false)
	res, err := h.rec.Reconcile(context.Background())
	if err != nil || res.Status != domain.TxPending {
		t.Fatalf("full apply: %v, %s", err, res.Status)
	}
	return res.TxID
}

// A tunnel disconnecting while a full apply is still on probation: the
// tunnel apply settles that apply first and is built from what it recorded,
// so the route it made yield to the tunnel comes back.
func TestTunnelApplyBesideAPendingApplyPutsBackWhatThatOneYielded(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	h.setTunnels(routing.TunnelInput{Name: "infra", Iface: "utun9", Routes: []string{"10.70.0.0/16"}})
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	h.profileP1(t, true)
	tx := h.fullApplyOnProbation(t)
	if got := h.kernel(t)["10.70.9.0/24"]; len(got) != 0 {
		t.Fatalf("the route didn't yield to the tunnel: %v", got)
	}

	h.setTunnels() // disconnected, inside the full apply's guard window
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := h.proto.Wait(tx); got != domain.TxCommitted {
		t.Fatalf("the full apply: %s, want settled by the tunnel apply", got)
	}
	if got := h.kernel(t)["10.70.9.0/24"]; len(got) != 1 || got[0] != "en0" {
		t.Errorf("the yielded route after the disconnect = %v, want it back via en0", got)
	}
}

// ...and one that disables a profile whose route had yielded: the tunnel
// apply doesn't put the disabled profile's route back.
func TestTunnelApplyBesideAPendingApplyLeavesWhatThatOneDisabled(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	h.setTunnels(routing.TunnelInput{Name: "infra", Iface: "utun9", Routes: []string{"10.70.0.0/16"}})
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	h.profileP1(t, true)
	tx := h.fullApplyOnProbation(t)
	h.clock.Advance(30 * time.Second)
	if got, _ := h.proto.Wait(tx); got != domain.TxCommitted {
		t.Fatalf("the enabling apply: %s", got)
	}

	h.profileP1(t, false)
	h.fullApplyOnProbation(t)
	h.setTunnels()
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.kernel(t)["10.70.9.0/24"]; len(got) != 0 {
		t.Errorf("the disabled profile's route was installed: %v", got)
	}
}

// A record outlives its profile: the user deletes a profile whose only route
// had yielded — the apply changes nothing and reports committed — and an
// unrelated change beside it then rolls back, taking the deletion's record
// with it. The disconnect's tunnel apply still doesn't install the deleted
// profile's route: only what a profile still routes is put back — even
// while another profile has a domain rule that never resolves.
func TestTunnelApplyNeverPutsBackADeletedProfilesRoute(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	h.setTunnels(routing.TunnelInput{Name: "infra", Iface: "utun9", Routes: []string{"10.70.0.0/16"}})
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.st.UpsertProfile(domain.Profile{ID: "p", Name: "p", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.70.9.0/24"}}}); err != nil {
		t.Fatal(err)
	}
	h.autoApply.Store(true)
	if res, err := h.rec.Reconcile(ctx); err != nil || res.Status != domain.TxCommitted {
		t.Fatalf("the apply recording p's yield: %v, %s", err, res.Status)
	}
	h.autoApply.Store(false)

	if err := h.st.UpsertProfile(domain.Profile{ID: "q", Name: "q", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.81.0.0/24"}}}); err != nil {
		t.Fatal(err)
	}
	if err := h.st.UpsertProfile(domain.Profile{ID: "typo", Name: "typo", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "192.0.2.0/24"}, {Type: domain.RuleDomain, Value: "typo.exampel.com"}}}); err != nil {
		t.Fatal(err)
	}
	txQ := h.fullApplyOnProbation(t)
	if err := h.st.DeleteProfile("p"); err != nil {
		t.Fatal(err)
	}
	h.autoApply.Store(true)
	if res, err := h.rec.Reconcile(ctx); err != nil || res.Status != domain.TxCommitted || len(res.Plan.Ops) != 0 {
		t.Fatalf("the deletion's apply: %v, %s, %d op(s)", err, res.Status, len(res.Plan.Ops))
	}
	h.autoApply.Store(false)
	h.blip(t) // q's watchdog rolls it back
	if got, _ := h.proto.Wait(txQ); got != domain.TxRolledBack {
		t.Fatalf("q's apply: %s, want rolled back", got)
	}

	h.setTunnels()
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.kernel(t)["10.70.9.0/24"]; len(got) != 0 {
		t.Errorf("the deleted profile's route was installed: %v", got)
	}
}

// What yielded may be a piece of a profile's rule: cut around one tunnel by
// a full apply, then yielded to a second tunnel. The profile still routes
// it, so it comes back when the second tunnel goes.
func TestTunnelApplyPutsBackAPieceOfAProfilesRule(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	if err := h.st.UpsertProfile(domain.Profile{ID: "inc", Name: "inc", Enabled: true, Mode: domain.ModeInclude,
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.0.0.0/8"}}}); err != nil {
		t.Fatal(err)
	}
	// "to 10.0.0.0/8" as a full apply cut it around the first tunnel.
	pieces := []string{"10.0.0.0/10", "10.64.0.0/14", "10.68.0.0/15", "10.71.0.0/16", "10.72.0.0/13", "10.80.0.0/12", "10.96.0.0/11", "10.128.0.0/9"}
	for _, p := range pieces {
		if err := h.prov.AddRule(ctx, domain.ManagedRule{PolicyRule: domain.PolicyRule{
			Priority: routing.ModelBRulePrio, Selector: "to " + p, Table: routing.ModelBTable, Family: domain.FamilyV4, Proto: "riftroute",
		}}); err != nil {
			t.Fatal(err)
		}
	}
	first := routing.TunnelInput{Name: "a", Iface: "utun9", Routes: []string{"10.70.0.0/16"}}
	h.setTunnels(first)
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	selectors := func() []string {
		rules, _ := h.prov.ListRules(ctx, domain.FamilyV4)
		var out []string
		for _, r := range rules {
			if r.Proto == "riftroute" {
				out = append(out, strings.TrimPrefix(r.Selector, "to "))
			}
		}
		sort.Strings(out)
		return out
	}
	want := append([]string(nil), pieces...)
	sort.Strings(want)
	if got := selectors(); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("rules with the first tunnel = %v", got)
	}

	h.prov.SetTunnelIface("utun8", "10.98.0.2", true)
	h.setTunnels(first, routing.TunnelInput{Name: "b", Iface: "utun8", Routes: []string{"10.80.0.0/16"}})
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	if got := selectors(); slices.Contains(got, "10.80.0.0/12") {
		t.Fatalf("the piece wasn't cut around the second tunnel: %v", got)
	}

	h.setTunnels(first)
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	if got := selectors(); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("rules after the second tunnel went = %v, want the pieces from before it", got)
	}
}

// A domain rule whose lookup comes back empty for a while — the cache is
// empty after a restart and DNS isn't up yet — isn't judged unrouted: its
// yielded route stays recorded, and comes back once the tunnel goes.
func TestTunnelApplyKeepsADomainsYieldWhileItsLookupFails(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	fr := dns.NewFakeResolver()
	fr.Set("corp.example.com", "10.70.1.5")
	h.svc.SetResolver(dns.NewCache(fr, time.Minute))
	h.setTunnels(routing.TunnelInput{Name: "infra", Iface: "utun9", Routes: []string{"10.70.0.0/16"}})
	if err := h.st.UpsertProfile(domain.Profile{ID: "p", Name: "p", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleDomain, Value: "corp.example.com"}}}); err != nil {
		t.Fatal(err)
	}
	tx := h.fullApplyOnProbation(t)
	h.clock.Advance(30 * time.Second)
	if got, _ := h.proto.Wait(tx); got != domain.TxCommitted {
		t.Fatalf("the full apply: %s", got)
	}
	if got := h.kernel(t)["10.70.1.5/32"]; len(got) != 0 {
		t.Fatalf("the domain's route didn't yield to the tunnel: %v", got)
	}

	h.svc.SetResolver(dns.NewCache(dns.NewFakeResolver(), time.Minute)) // restarted; DNS not up
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	h.svc.SetResolver(dns.NewCache(fr, time.Minute)) // DNS is back
	h.setTunnels()
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.kernel(t)["10.70.1.5/32"]; len(got) != 1 || got[0] != "en0" {
		t.Errorf("the domain's route after the disconnect = %v, want it back via en0", got)
	}
}

// An include rule a tunnel apply records is read from the kernel, which
// keeps no profile: the record gives it the profile that routes it. Deleted
// later, that profile's rule stays out after the disconnect — even while
// another include profile has a domain rule that never resolves.
func TestTunnelApplyNeverPutsBackADeletedProfilesRule(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	h.svc.SetResolver(dns.NewCache(dns.NewFakeResolver(), time.Minute)) // typo.exampel.com never resolves
	for _, p := range []domain.Profile{
		{ID: "gone", Name: "gone", Enabled: true, Mode: domain.ModeInclude, Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "10.70.9.0/24"}}},
		{ID: "typo", Name: "typo", Enabled: true, Mode: domain.ModeInclude, Rules: []domain.Rule{
			{Type: domain.RuleCIDR, Value: "192.0.2.0/24"}, {Type: domain.RuleDomain, Value: "typo.exampel.com"}}},
	} {
		if err := h.st.UpsertProfile(p); err != nil {
			t.Fatal(err)
		}
	}
	for _, dst := range []string{"10.70.9.0/24", "192.0.2.0/24"} { // as a full apply installed them
		if err := h.prov.AddRule(ctx, domain.ManagedRule{PolicyRule: domain.PolicyRule{
			Priority: routing.ModelBRulePrio, Selector: "to " + dst, Table: routing.ModelBTable, Family: domain.FamilyV4, Proto: "riftroute",
		}}); err != nil {
			t.Fatal(err)
		}
	}
	h.setTunnels(routing.TunnelInput{Name: "infra", Iface: "utun9", Routes: []string{"10.70.0.0/16"}})
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	selectors := func() []string {
		rules, _ := h.prov.ListRules(ctx, domain.FamilyV4)
		var out []string
		for _, r := range rules {
			if r.Proto == "riftroute" {
				out = append(out, r.Selector)
			}
		}
		sort.Strings(out)
		return out
	}
	if got := selectors(); slices.Contains(got, "to 10.70.9.0/24") {
		t.Fatalf("the rule didn't yield to the tunnel: %v", got)
	}

	if err := h.st.DeleteProfile("gone"); err != nil {
		t.Fatal(err)
	}
	h.setTunnels()
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	if got := selectors(); slices.Contains(got, "to 10.70.9.0/24") {
		t.Errorf("the deleted profile's rule came back: %v", got)
	}
}

// ...and while its profile stays, it comes back — even when that profile's
// domain can't be looked up at the disconnect (a restart, DNS not up yet):
// attributed, it's held as its own profile's; judged by coverage alone it
// would be dropped, and that host's traffic would leave outside the VPN.
func TestTunnelApplyPutsBackAnAttributedRuleWhileItsLookupFails(t *testing.T) {
	h := newTunnelHarness(t)
	ctx := context.Background()
	fr := dns.NewFakeResolver()
	fr.Set("corp.example.com", "10.70.1.5")
	h.svc.SetResolver(dns.NewCache(fr, time.Minute))
	if err := h.st.UpsertProfile(domain.Profile{ID: "p", Name: "p", Enabled: true, Mode: domain.ModeInclude,
		Rules: []domain.Rule{{Type: domain.RuleDomain, Value: "corp.example.com"}}}); err != nil {
		t.Fatal(err)
	}
	if err := h.prov.AddRule(ctx, domain.ManagedRule{PolicyRule: domain.PolicyRule{ // as a full apply installed it
		Priority: routing.ModelBRulePrio, Selector: "to 10.70.1.5/32", Table: routing.ModelBTable, Family: domain.FamilyV4, Proto: "riftroute",
	}}); err != nil {
		t.Fatal(err)
	}
	h.setTunnels(routing.TunnelInput{Name: "infra", Iface: "utun9", Routes: []string{"10.70.0.0/16"}})
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}

	h.svc.SetResolver(dns.NewCache(dns.NewFakeResolver(), time.Minute)) // restarted; DNS not up
	h.setTunnels()
	if err := h.rec.ApplyTunnels(ctx); err != nil {
		t.Fatal(err)
	}
	rules, _ := h.prov.ListRules(ctx, domain.FamilyV4)
	var ours []string
	for _, r := range rules {
		if r.Proto == "riftroute" {
			ours = append(ours, r.Selector)
		}
	}
	if len(ours) != 1 || ours[0] != "to 10.70.1.5/32" {
		t.Errorf("rules after the disconnect = %q, want p's back", ours)
	}
}
