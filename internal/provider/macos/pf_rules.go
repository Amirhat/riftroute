// Pure PF rule generation + parsing for the macOS backend. Deliberately NOT
// build-tagged so it unit-tests on any OS (like linux_parse.go): the darwin-only
// glue in pf.go shells out to pfctl and feeds the bytes here.
//
// macOS has no policy-routing tables or fwmark; the Darwin-native way to steer
// selected traffic into a tunnel is PF `route-to` in a dedicated anchor. RiftRoute
// owns one anchor ("riftroute") — its exclusive namespace — and marks every rule
// with the fixed label "riftroute" (PF caps labels at 63 chars — verified against
// the real pfctl: "rule label too long (max 63 chars)" — so identity cannot ride
// in the label). A rule's identity is instead parsed back from pfctl's canonical
// rule text, which is stable for the narrow shape we render: pfctl echoes our
// rules back with `flags S/SA keep state` appended and full-length host prefixes
// stripped (`to 1.2.3.4/32` → `to 1.2.3.4`), both handled by the parser below.
package macos

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/routing"
)

const (
	// pfAnchorName is the dedicated PF anchor RiftRoute owns for policy routing.
	pfAnchorName = "riftroute"
	// pfOwnerLabel marks a rule inside the anchor as ours. Fixed (not per-rule):
	// PF labels are limited to 63 chars, so identity lives in the rule text.
	pfOwnerLabel = "riftroute"

	// The pf.conf hook is a single marked, reversible block that references our
	// anchor so its rules are actually evaluated (an unreferenced anchor is inert).
	pfHookBegin = "# >>> riftroute (managed — do not edit) >>>"
	pfHookEnd   = "# <<< riftroute (managed — do not edit) <<<"
)

// pfRuleKey is the identity used to match/dedupe owned rules. It delegates to
// routing.RuleKey so the engine's reconcile diffing and the provider's anchor
// read-modify-write share ONE definition of "the same rule" (including the
// route-to interface and gateway).
func pfRuleKey(r domain.PolicyRule) string { return routing.RuleKey(r) }

// renderPFRule renders one owned route-to rule. The rule only ever PASSES matched
// traffic into the tunnel (never blocks), so an orphaned rule can steer — but can
// never brick — connectivity; a dead tunnel just blackholes its own matched dests
// (fail-safe for include mode: matched traffic must not leak to the physical
// path) until teardown flushes the anchor.
func renderPFRule(r domain.PolicyRule) string {
	af := "inet"
	if r.Family == domain.FamilyV6 {
		af = "inet6"
	}
	// pfctl grammar (verified with parse-only pfctl -nf): with a next-hop gateway
	// the target is parenthesized `route-to (utun4 10.8.0.1)`; without one, the
	// parens form is a SYNTAX ERROR and it must be the bare `route-to utun4`.
	target := r.RouteToIface
	if r.RouteToGW != "" {
		target = "(" + r.RouteToIface + " " + r.RouteToGW + ")"
	}
	// Selector forms rendered (validated upstream by the engine): "to <cidr>" or
	// "user <uid>". Render "from any" explicitly to match pfctl's canonical echo.
	sel := r.Selector
	if strings.HasPrefix(sel, "to ") {
		sel = "from any " + sel
	} else if strings.HasPrefix(sel, "user ") {
		sel = "from any to any " + sel
	}
	return fmt.Sprintf("pass out quick route-to %s %s %s label %q", target, af, sel, pfOwnerLabel)
}

// RenderAnchor renders the full anchor ruleset for the given owned rules, in a
// deterministic order so identical inputs produce byte-identical output.
func RenderAnchor(rules []domain.PolicyRule) string {
	rs := append([]domain.PolicyRule{}, rules...)
	sort.SliceStable(rs, func(i, j int) bool { return pfRuleKey(rs[i]) < pfRuleKey(rs[j]) })
	var b strings.Builder
	for _, r := range rs {
		b.WriteString(renderPFRule(r))
		b.WriteByte('\n')
	}
	return b.String()
}

// reRouteTo matches both pfctl target shapes: parenthesized `route-to (utun4
// 10.8.0.1)` (with gateway) and bare `route-to utun4` (interface only).
var reRouteTo = regexp.MustCompile(`route-to\s+(?:\(([^)]+)\)|(\S+))`)

// parseAnchorRules parses `pfctl -a riftroute -sr` output back into the owned
// PolicyRules. Only lines carrying our ownership label are considered; identity
// is recovered from pfctl's canonical rule text, tolerating its normalizations
// (appended `flags S/SA keep state`, `user = 501` spacing, and host prefixes
// printed without their /32 / /128). Duplicates (by rule identity) collapse.
func parseAnchorRules(out string) []domain.PolicyRule {
	var rules []domain.PolicyRule
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		label, ok := extractLabel(line)
		if !ok || label != pfOwnerLabel {
			continue
		}
		pr, ok := parsePFRuleText(line)
		if !ok {
			continue
		}
		k := pfRuleKey(pr)
		if seen[k] {
			continue
		}
		seen[k] = true
		rules = append(rules, pr)
	}
	return rules
}

// parsePFRuleText recovers a PolicyRule from one canonical pfctl rule line.
func parsePFRuleText(line string) (domain.PolicyRule, bool) {
	m := reRouteTo.FindStringSubmatch(line)
	if m == nil {
		return domain.PolicyRule{}, false
	}
	rawTarget := m[1] // parenthesized form (iface [gw])
	if rawTarget == "" {
		rawTarget = m[2] // bare-interface form
	}
	target := strings.Fields(rawTarget)
	if len(target) == 0 {
		return domain.PolicyRule{}, false
	}
	pr := domain.PolicyRule{
		Priority:     routing.ModelBRulePrio,
		Proto:        "riftroute",
		RouteToIface: target[0],
	}
	if len(target) > 1 {
		pr.RouteToGW = target[1]
	}

	fam := domain.FamilyV4
	if strings.Contains(line, " inet6 ") {
		fam = domain.FamilyV6
	}
	pr.Family = fam

	fields := strings.Fields(line)
	// user selector: "user 501" or pfctl-normalized "user = 501".
	for i, f := range fields {
		if f == "user" && i+1 < len(fields) {
			val := fields[i+1]
			if val == "=" && i+2 < len(fields) {
				val = fields[i+2]
			}
			pr.Selector = "user " + val
			return pr, true
		}
	}
	// destination selector: "to <addr>" with addr != "any"; pfctl strips a
	// full-length prefix, so a bare IP is normalized back to /32 (v4) or /128.
	for i, f := range fields {
		if f == "to" && i+1 < len(fields) {
			dst := fields[i+1]
			if dst == "any" {
				continue
			}
			pr.Selector = "to " + normalizePFDst(dst)
			return pr, true
		}
	}
	return domain.PolicyRule{}, false
}

// normalizePFDst re-appends the full-length prefix pfctl strips from host
// addresses, so identities round-trip ("to 1.2.3.4/32" prints as "to 1.2.3.4").
func normalizePFDst(dst string) string {
	if strings.Contains(dst, "/") {
		return dst
	}
	a, err := netip.ParseAddr(dst)
	if err != nil {
		return dst
	}
	return netip.PrefixFrom(a, a.BitLen()).String()
}

// extractLabel pulls the value out of a `label "…"` token in a pfctl rule line.
func extractLabel(line string) (string, bool) {
	const tok = `label "`
	i := strings.Index(line, tok)
	if i < 0 {
		return "", false
	}
	rest := line[i+len(tok):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return "", false
	}
	return rest[:j], true
}

// --- pf.conf hook (pure transforms; the darwin glue does the file IO) ---

func pfHookBlock() string {
	return pfHookBegin + "\n" + `anchor "` + pfAnchorName + `"` + "\n" + pfHookEnd + "\n"
}

// pfHasHook reports whether pf.conf already contains our managed block.
func pfHasHook(conf string) bool { return strings.Contains(conf, pfHookBegin) }

// pfInsertHook appends our anchor reference to pf.conf (idempotent). It goes at
// the END so it follows any scrub/nat/rdr anchors — macOS pf requires filter
// anchors after those.
func pfInsertHook(conf string) string {
	if pfHasHook(conf) {
		return conf
	}
	if conf != "" && !strings.HasSuffix(conf, "\n") {
		conf += "\n"
	}
	return conf + pfHookBlock()
}

// pfRemoveHook strips our managed block from pf.conf (idempotent), leaving the
// rest of the file exactly as the user had it.
func pfRemoveHook(conf string) string {
	start := strings.Index(conf, pfHookBegin)
	if start < 0 {
		return conf
	}
	end := strings.Index(conf, pfHookEnd)
	if end < 0 {
		return conf[:start] // truncated block — drop from the marker on
	}
	// Everything before the block is preserved verbatim (so an appended block is
	// removed cleanly); consume the single newline that terminates the end marker.
	tail := strings.TrimPrefix(conf[end+len(pfHookEnd):], "\n")
	return conf[:start] + tail
}
