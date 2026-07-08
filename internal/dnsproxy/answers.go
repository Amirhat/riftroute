package dnsproxy

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"sync"
)

// AnswerStore accumulates learned wildcard answers (rule → fqdn → addrs),
// bounded per rule, and serializes for persistence so learned routes survive
// a daemon restart (until re-learned or the rule is removed).
type AnswerStore struct {
	mu         sync.Mutex
	m          map[string]map[string][]netip.Addr
	maxPerRule int
}

// NewAnswerStore builds an empty store; maxPerRule bounds distinct learned
// names per wildcard (oldest-agnostic drop: new names are ignored at the cap,
// which keeps the route table bounded).
func NewAnswerStore(maxPerRule int) *AnswerStore {
	if maxPerRule <= 0 {
		maxPerRule = 256
	}
	return &AnswerStore{m: map[string]map[string][]netip.Addr{}, maxPerRule: maxPerRule}
}

// Add records addrs for fqdn under rule, reporting whether anything changed.
func (s *AnswerStore) Add(rule, fqdn string, addrs []netip.Addr) bool {
	if len(addrs) == 0 {
		return false
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Compare(addrs[j]) < 0 })
	s.mu.Lock()
	defer s.mu.Unlock()
	names := s.m[rule]
	if names == nil {
		names = map[string][]netip.Addr{}
		s.m[rule] = names
	}
	prev, known := names[fqdn]
	if !known && len(names) >= s.maxPerRule {
		return false // bounded: protect the route table and the DB
	}
	if known && equalAddrs(prev, addrs) {
		return false
	}
	// Merge rather than replace: CDNs rotate answers, and a route for an IP a
	// live connection is pinned to must not flap away between lookups.
	merged := mergeAddrs(prev, addrs)
	if known && equalAddrs(prev, merged) {
		return false
	}
	names[fqdn] = merged
	return true
}

// IPs returns every learned address for rule, as strings, deduplicated.
func (s *AnswerStore) IPs(rule string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, addrs := range s.m[rule] {
		for _, a := range addrs {
			if k := a.String(); !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Names returns how many distinct names have been learned for rule.
func (s *AnswerStore) Names(rule string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m[rule])
}

// Prune drops rules that are no longer configured, reporting change.
func (s *AnswerStore) Prune(active []string) bool {
	keep := map[string]bool{}
	for _, r := range active {
		keep[strings.ToLower(r)] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for rule := range s.m {
		if !keep[strings.ToLower(rule)] {
			delete(s.m, rule)
			changed = true
		}
	}
	return changed
}

// Marshal serializes the learned set (rule → fqdn → addr strings).
func (s *AnswerStore) Marshal() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]map[string][]string{}
	for rule, names := range s.m {
		out[rule] = map[string][]string{}
		for fqdn, addrs := range names {
			ss := make([]string, 0, len(addrs))
			for _, a := range addrs {
				ss = append(ss, a.String())
			}
			out[rule][fqdn] = ss
		}
	}
	return json.Marshal(out)
}

// Load replaces the learned set from Marshal output (best-effort).
func (s *AnswerStore) Load(data []byte) error {
	var in map[string]map[string][]string
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	m := map[string]map[string][]netip.Addr{}
	for rule, names := range in {
		m[rule] = map[string][]netip.Addr{}
		for fqdn, ss := range names {
			var addrs []netip.Addr
			for _, v := range ss {
				if a, err := netip.ParseAddr(v); err == nil {
					addrs = append(addrs, a)
				}
			}
			if len(addrs) > 0 {
				m[rule][fqdn] = addrs
			}
		}
	}
	s.mu.Lock()
	s.m = m
	s.mu.Unlock()
	return nil
}

func equalAddrs(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mergeAddrs(prev, next []netip.Addr) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, a := range prev {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, a := range next {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
	return out
}
