package routing

import (
	"net/netip"
	"testing"
)

func pfxs(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func keys(ps []netip.Prefix) map[string]bool {
	m := map[string]bool{}
	for _, p := range ps {
		m[p.String()] = true
	}
	return m
}

func TestAggregateNeverExpands(t *testing.T) {
	// A /8 must stay a /8 — never expanded to host routes (spec §5.2).
	got := Aggregate(pfxs("10.0.0.0/8"))
	if len(got) != 1 || got[0].String() != "10.0.0.0/8" {
		t.Fatalf("got %v", got)
	}
}

func TestAggregateMergesSiblings(t *testing.T) {
	got := Aggregate(pfxs("10.0.0.0/24", "10.0.1.0/24"))
	if len(got) != 1 || got[0].String() != "10.0.0.0/23" {
		t.Fatalf("siblings should merge to /23, got %v", got)
	}
	// /25 halves merge to /24.
	got = Aggregate(pfxs("10.0.0.0/25", "10.0.0.128/25"))
	if len(got) != 1 || got[0].String() != "10.0.0.0/24" {
		t.Fatalf("/25 halves should merge to /24, got %v", got)
	}
}

func TestAggregateDoesNotMergeNonSiblings(t *testing.T) {
	// 10.0.0.0/24 and 10.0.2.0/24 are NOT the two halves of a /23 — merging would
	// wrongly capture 10.0.1.0/24, which the user did not specify.
	got := Aggregate(pfxs("10.0.0.0/24", "10.0.2.0/24"))
	if len(got) != 2 {
		t.Fatalf("non-siblings must NOT merge, got %v", got)
	}
}

func TestAggregateDropsContained(t *testing.T) {
	got := Aggregate(pfxs("10.0.0.0/8", "10.1.0.0/16", "10.0.0.0/24"))
	if len(got) != 1 || got[0].String() != "10.0.0.0/8" {
		t.Fatalf("contained prefixes should drop, got %v", got)
	}
}

func TestAggregateChainMerge(t *testing.T) {
	// Four /26 covering a /24 should collapse all the way to /24.
	got := Aggregate(pfxs("10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/26", "10.0.0.192/26"))
	if len(got) != 1 || got[0].String() != "10.0.0.0/24" {
		t.Fatalf("four /26 should chain-merge to /24, got %v", got)
	}
}

func TestAggregateMixedFamilies(t *testing.T) {
	got := Aggregate(pfxs("10.0.0.0/24", "10.0.1.0/24", "2001:db8::/33", "2001:db8:8000::/33"))
	k := keys(got)
	if !k["10.0.0.0/23"] || !k["2001:db8::/32"] {
		t.Fatalf("v4 and v6 should each aggregate independently, got %v", got)
	}
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}
