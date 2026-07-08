package dnsproxy

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Default bounds. addrTTL expires a learned address that hasn't been re-seen —
// without it a CDN wildcard (rotating A records every lookup) would accumulate
// dead IPs forever, bloating the route table and the persisted blob. The name
// and per-name address caps are hard ceilings; both evict the OLDEST entry so
// a burst of junk lookups can't permanently freeze out a real name.
const (
	defaultAddrTTL         = 6 * time.Hour
	defaultMaxNamesPerRule = 256
	defaultMaxAddrsPerName = 16
)

type addrSeen struct {
	addr netip.Addr
	seen time.Time
}

type nameEntry struct {
	addrs    []addrSeen
	lastSeen time.Time
}

// AnswerStore accumulates learned wildcard answers (rule → fqdn → addrs) with
// per-address TTL and recency-bounded caps, and serializes for persistence so
// learned routes survive a daemon restart (until they expire or the rule is
// removed).
type AnswerStore struct {
	mu       sync.Mutex
	m        map[string]map[string]*nameEntry
	maxNames int
	maxAddrs int
	ttl      time.Duration
	now      func() time.Time
}

// NewAnswerStore builds an empty store; maxNames bounds distinct learned names
// per wildcard.
func NewAnswerStore(maxNames int) *AnswerStore {
	if maxNames <= 0 {
		maxNames = defaultMaxNamesPerRule
	}
	return &AnswerStore{
		m:        map[string]map[string]*nameEntry{},
		maxNames: maxNames,
		maxAddrs: defaultMaxAddrsPerName,
		ttl:      defaultAddrTTL,
		now:      time.Now,
	}
}

// SetClock overrides the time source (tests).
func (s *AnswerStore) SetClock(now func() time.Time) { s.now = now }

// Add records addrs for fqdn under rule, reporting whether the resulting
// address set changed (so the caller can decide whether to reconcile/persist).
func (s *AnswerStore) Add(rule, fqdn string, addrs []netip.Addr) bool {
	if len(addrs) == 0 {
		return false
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	names := s.m[rule]
	if names == nil {
		names = map[string]*nameEntry{}
		s.m[rule] = names
	}
	e, known := names[fqdn]
	if !known {
		if len(names) >= s.maxNames {
			// Evict the least-recently-seen name rather than reject the new one,
			// so junk lookups can't permanently block a real name from learning.
			s.evictOldestName(names)
		}
		e = &nameEntry{}
		names[fqdn] = e
	}
	before := e.activeAddrs(now, s.ttl)
	// Refresh/insert each observed address' seen time.
	for _, a := range addrs {
		e.touch(a, now)
	}
	e.lastSeen = now
	e.expire(now, s.ttl)
	e.capAddrs(s.maxAddrs)
	after := e.activeAddrs(now, s.ttl)
	return !equalAddrs(before, after)
}

// IPs returns every currently-live learned address for rule, deduplicated.
func (s *AnswerStore) IPs(rule string) []string {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, e := range s.m[rule] {
		for _, a := range e.activeAddrs(now, s.ttl) {
			if k := a.String(); !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

// GC drops expired addresses and now-empty names across all rules, reporting
// whether anything changed (the daemon can then reconcile/persist).
func (s *AnswerStore) GC() bool {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for rule, names := range s.m {
		for fqdn, e := range names {
			n := len(e.addrs)
			e.expire(now, s.ttl)
			if len(e.addrs) != n {
				changed = true
			}
			if len(e.addrs) == 0 {
				delete(names, fqdn)
				changed = true
			}
		}
		if len(names) == 0 {
			delete(s.m, rule)
		}
	}
	return changed
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

// --- nameEntry helpers (caller holds s.mu) ---

func (e *nameEntry) touch(a netip.Addr, now time.Time) {
	for i := range e.addrs {
		if e.addrs[i].addr == a {
			e.addrs[i].seen = now
			return
		}
	}
	e.addrs = append(e.addrs, addrSeen{addr: a, seen: now})
}

func (e *nameEntry) expire(now time.Time, ttl time.Duration) {
	kept := e.addrs[:0]
	for _, as := range e.addrs {
		if now.Sub(as.seen) < ttl {
			kept = append(kept, as)
		}
	}
	e.addrs = kept
}

// capAddrs keeps the maxAddrs most-recently-seen addresses.
func (e *nameEntry) capAddrs(maxAddrs int) {
	if maxAddrs <= 0 || len(e.addrs) <= maxAddrs {
		return
	}
	sort.Slice(e.addrs, func(i, j int) bool { return e.addrs[i].seen.After(e.addrs[j].seen) })
	e.addrs = e.addrs[:maxAddrs]
}

func (e *nameEntry) activeAddrs(now time.Time, ttl time.Duration) []netip.Addr {
	var out []netip.Addr
	for _, as := range e.addrs {
		if now.Sub(as.seen) < ttl {
			out = append(out, as.addr)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
	return out
}

func (s *AnswerStore) evictOldestName(names map[string]*nameEntry) {
	var oldest string
	var oldestAt time.Time
	first := true
	for fqdn, e := range names {
		if first || e.lastSeen.Before(oldestAt) {
			oldest, oldestAt, first = fqdn, e.lastSeen, false
		}
	}
	if oldest != "" {
		delete(names, oldest)
	}
}

// --- persistence ---

type persistedAddr struct {
	IP   string    `json:"ip"`
	Seen time.Time `json:"seen"`
}
type persistedName struct {
	Addrs    []persistedAddr `json:"addrs"`
	LastSeen time.Time       `json:"last_seen"`
}

// Marshal serializes the learned set with timestamps (so TTL survives restart).
func (s *AnswerStore) Marshal() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]map[string]persistedName{}
	for rule, names := range s.m {
		out[rule] = map[string]persistedName{}
		for fqdn, e := range names {
			pn := persistedName{LastSeen: e.lastSeen}
			for _, as := range e.addrs {
				pn.Addrs = append(pn.Addrs, persistedAddr{IP: as.addr.String(), Seen: as.seen})
			}
			out[rule][fqdn] = pn
		}
	}
	return json.Marshal(out)
}

// Load replaces the learned set from Marshal output (best-effort), dropping
// already-expired addresses on the way in.
func (s *AnswerStore) Load(data []byte) error {
	var in map[string]map[string]persistedName
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	now := s.now()
	m := map[string]map[string]*nameEntry{}
	for rule, names := range in {
		m[rule] = map[string]*nameEntry{}
		for fqdn, pn := range names {
			e := &nameEntry{lastSeen: pn.LastSeen}
			for _, pa := range pn.Addrs {
				a, err := netip.ParseAddr(pa.IP)
				if err != nil || now.Sub(pa.Seen) >= s.ttl {
					continue
				}
				e.addrs = append(e.addrs, addrSeen{addr: a, seen: pa.Seen})
			}
			if len(e.addrs) > 0 {
				m[rule][fqdn] = e
			}
		}
		if len(m[rule]) == 0 {
			delete(m, rule)
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
