package routing

import (
	"net/netip"
	"sort"
)

// Aggregate reduces a set of prefixes to the minimal equivalent set so the
// kernel table stays small (spec §5.2). It is deliberately conservative and
// SAFE: it only (1) drops a prefix already covered by another, and (2) merges
// the two complete halves of a parent into the parent. It NEVER introduces
// address space that the input didn't already cover — so an aggregated bypass
// can never capture destinations the user didn't specify. v4 and v6 are
// aggregated independently.
func Aggregate(prefixes []netip.Prefix) []netip.Prefix {
	norm := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		if p.IsValid() {
			norm = append(norm, p.Masked())
		}
	}
	sortPrefixes(norm)

	// 1. Drop prefixes contained in an earlier (shorter) prefix.
	var kept []netip.Prefix
	for _, p := range norm {
		covered := false
		for _, q := range kept {
			if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, p)
		}
	}

	// 2. Repeatedly merge complete sibling pairs into their parent.
	for {
		merged, changed := mergeOnce(kept)
		kept = merged
		if !changed {
			break
		}
	}
	return kept
}

func mergeOnce(in []netip.Prefix) ([]netip.Prefix, bool) {
	sortPrefixes(in)
	used := make([]bool, len(in))
	var out []netip.Prefix
	changed := false
	for i := 0; i < len(in); i++ {
		if used[i] {
			continue
		}
		p := in[i]
		if p.Bits() > 0 && i+1 < len(in) && !used[i+1] {
			q := in[i+1]
			if p.Bits() == q.Bits() {
				parent := netip.PrefixFrom(p.Addr(), p.Bits()-1).Masked()
				// p and q are the two halves of parent iff parent contains both
				// and they are distinct.
				if parent.Contains(p.Addr()) && parent.Contains(q.Addr()) && p.Addr() != q.Addr() {
					out = append(out, parent)
					used[i], used[i+1] = true, true
					changed = true
					continue
				}
			}
		}
		out = append(out, p)
		used[i] = true
	}
	return out, changed
}

func sortPrefixes(p []netip.Prefix) {
	sort.Slice(p, func(i, j int) bool {
		if p[i].Addr().Is4() != p[j].Addr().Is4() {
			return p[i].Addr().Is4() // v4 before v6
		}
		if c := p[i].Addr().Compare(p[j].Addr()); c != 0 {
			return c < 0
		}
		return p[i].Bits() < p[j].Bits()
	})
}
