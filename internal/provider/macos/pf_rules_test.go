package macos

import (
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

func sampleRules() []domain.PolicyRule {
	return []domain.PolicyRule{
		{Priority: 5252, Selector: "to 10.0.0.0/8", Family: domain.FamilyV4, Proto: "riftroute", RouteToIface: "utun4", RouteToGW: "10.8.0.1"},
		{Priority: 5252, Selector: "to 172.16.0.0/12", Family: domain.FamilyV4, Proto: "riftroute", RouteToIface: "utun4"}, // on-link (no gw)
		{Priority: 5252, Selector: "to fd00::/8", Family: domain.FamilyV6, Proto: "riftroute", RouteToIface: "utun4"},
		{Priority: 5252, Selector: "user 501", Family: domain.FamilyV4, Proto: "riftroute", RouteToIface: "utun4"},
	}
}

// PF caps rule labels at 63 chars (verified against the real pfctl: "rule label
// too long (max 63 chars)") — the ownership label must stay a short constant.
func TestPFLabelWithinPFLimit(t *testing.T) {
	if len(pfOwnerLabel) > 63 {
		t.Fatalf("pf label %q exceeds PF's 63-char limit", pfOwnerLabel)
	}
	for _, r := range sampleRules() {
		line := renderPFRule(r)
		label, ok := extractLabel(line)
		if !ok {
			t.Fatalf("rendered rule has no label: %s", line)
		}
		if len(label) > 63 {
			t.Errorf("label %q (%d chars) exceeds PF's 63-char limit", label, len(label))
		}
	}
}

func TestRenderPFRule(t *testing.T) {
	r := domain.PolicyRule{Priority: 5252, Selector: "to 10.0.0.0/8", Family: domain.FamilyV4, RouteToIface: "utun4", RouteToGW: "10.8.0.1"}
	line := renderPFRule(r)
	for _, want := range []string{"pass out quick", "route-to (utun4 10.8.0.1)", "inet", "from any to 10.0.0.0/8", `label "riftroute"`} {
		if !strings.Contains(line, want) {
			t.Errorf("rendered rule missing %q:\n%s", want, line)
		}
	}
	// v6 rules use inet6; on-link (no gw) omits the address; user rules render a
	// full from-any-to-any match.
	// Gateway-less targets MUST render parenless — `route-to (utun4)` is a pfctl
	// syntax error (verified against the real parser).
	v6 := renderPFRule(domain.PolicyRule{Selector: "to fd00::/8", Family: domain.FamilyV6, RouteToIface: "utun4"})
	if !strings.Contains(v6, "inet6") || !strings.Contains(v6, "route-to utun4 ") || strings.Contains(v6, "(utun4)") {
		t.Errorf("v6/on-link render wrong:\n%s", v6)
	}
	user := renderPFRule(domain.PolicyRule{Selector: "user 501", Family: domain.FamilyV4, RouteToIface: "utun4"})
	if !strings.Contains(user, "from any to any user 501") {
		t.Errorf("user render wrong:\n%s", user)
	}
}

// TestAnchorRoundTripCanonical feeds the parser pfctl's CANONICAL echo of our
// rules — captured verbatim from a real `pfctl -nvf -` run: `flags S/SA keep
// state` is appended, host prefixes are printed bare (1.2.3.4, not 1.2.3.4/32),
// gateway-less targets echo parenless (`route-to utun4`), and user matches
// collapse to `inet all user = 501`.
func TestAnchorRoundTripCanonical(t *testing.T) {
	canonical := strings.Join([]string{
		`pass out quick route-to (utun4 10.8.0.1) inet from any to 10.0.0.0/8 flags S/SA keep state label "riftroute"`,
		`pass out quick route-to utun4 inet from any to 172.16.0.0/12 flags S/SA keep state label "riftroute"`,
		`pass out quick route-to utun4 inet6 from any to fd00::/8 flags S/SA keep state label "riftroute"`,
		`pass out quick route-to utun4 inet all user = 501 flags S/SA keep state label "riftroute"`,
	}, "\n")

	got := parseAnchorRules(canonical)
	if len(got) != 4 {
		t.Fatalf("parsed %d rules, want 4:\n%+v", len(got), got)
	}
	want := map[string]bool{}
	for _, r := range sampleRules() {
		want[pfRuleKey(r)] = true
	}
	for _, r := range got {
		if !want[pfRuleKey(r)] {
			t.Errorf("parsed rule does not match any desired identity: %+v", r)
		}
		if r.Proto != "riftroute" {
			t.Errorf("parsed rule must be tagged owned; got proto %q", r.Proto)
		}
	}
}

// TestParseHostPrefixNormalization: pfctl strips full-length prefixes, so a host
// rule echoes as a bare IP; the parser must restore /32 (v4) and /128 (v6) or
// reconcile would forever see the rule as "different" and churn.
func TestParseHostPrefixNormalization(t *testing.T) {
	out := `pass out quick route-to (utun4 10.8.0.1) inet from any to 1.2.3.4 flags S/SA keep state label "riftroute"` + "\n" +
		`pass out quick route-to utun4 inet6 from any to 2001:db8::1 flags S/SA keep state label "riftroute"`
	got := parseAnchorRules(out)
	if len(got) != 2 {
		t.Fatalf("parsed %d rules, want 2", len(got))
	}
	if got[0].Selector != "to 1.2.3.4/32" {
		t.Errorf("v4 host not normalized: %q", got[0].Selector)
	}
	if got[1].Selector != "to 2001:db8::1/128" {
		t.Errorf("v6 host not normalized: %q", got[1].Selector)
	}
}

func TestParseAnchorIgnoresForeignAndDedups(t *testing.T) {
	out := strings.Join([]string{
		`pass out quick route-to utun4 inet from any to 10.0.0.0/8 label "riftroute"`,
		`pass out quick route-to utun4 inet from any to 10.0.0.0/8 label "riftroute"`, // duplicate echo
		`pass in all label "something-else"`,                                          // foreign label
		`block drop out quick inet from any to 203.0.113.0/24`,                        // no label
		`nonsense line`,
	}, "\n")
	got := parseAnchorRules(out)
	if len(got) != 1 {
		t.Fatalf("got %d rules, want 1 (foreign ignored, duplicates collapsed): %+v", len(got), got)
	}
}

func TestPFConfHookRoundTrip(t *testing.T) {
	// A representative macOS pf.conf (Apple's default anchors precede ours).
	const base = `scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
`
	if pfHasHook(base) {
		t.Fatal("base pf.conf should not report our hook")
	}
	with := pfInsertHook(base)
	if !pfHasHook(with) {
		t.Fatal("inserted hook not detected")
	}
	if !strings.Contains(with, `anchor "riftroute"`) {
		t.Errorf("hook missing anchor reference:\n%s", with)
	}
	// Our filter anchor must come AFTER Apple's anchors (append at end).
	if strings.Index(with, `anchor "riftroute"`) < strings.LastIndex(with, `anchor "com.apple/*"`) {
		t.Error("riftroute anchor must follow the com.apple anchors")
	}
	// Idempotent insert.
	if pfInsertHook(with) != with {
		t.Error("pfInsertHook is not idempotent")
	}
	// Remove restores the original byte-for-byte.
	if restored := pfRemoveHook(with); restored != base {
		t.Errorf("remove did not restore original:\n--- want ---\n%s\n--- got ---\n%s", base, restored)
	}
	// Remove is idempotent / safe when absent.
	if pfRemoveHook(base) != base {
		t.Error("pfRemoveHook altered a file without our block")
	}
}
