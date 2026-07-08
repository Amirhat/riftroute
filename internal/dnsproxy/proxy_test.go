package dnsproxy

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeUpstream is a loopback DNS server answering every A query with answer.
func fakeUpstream(t *testing.T, answer netip.Addr) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if err := q.Unpack(buf[:n]); err != nil || len(q.Questions) == 0 {
				continue
			}
			resp := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true},
				Questions: q.Questions,
				Answers: []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{
						Name: q.Questions[0].Name, Type: dnsmessage.TypeA,
						Class: dnsmessage.ClassINET, TTL: 60,
					},
					Body: &dnsmessage.AResource{A: answer.As4()},
				}},
			}
			out, err := resp.Pack()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(out, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func buildQuery(t *testing.T, name string) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 7, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
		}},
	}
	out, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func askProxy(t *testing.T, port int, query []byte) dnsmessage.Message {
	t.Helper()
	c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(buf[:n]); err != nil {
		t.Fatal(err)
	}
	return msg
}

// The headline behavior: a lookup of a wildcard subdomain is answered
// normally AND its addresses are learned for routing.
func TestProxyForwardsAndLearns(t *testing.T) {
	answer := netip.MustParseAddr("198.51.100.7")
	up := fakeUpstream(t, answer)

	var mu sync.Mutex
	learned := map[string][]netip.Addr{}
	p := New(nil, func(rule, fqdn string, addrs []netip.Addr) {
		mu.Lock()
		learned[rule+"|"+fqdn] = addrs
		mu.Unlock()
	})
	port, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Stop)
	p.SetUpstreams([]string{up})
	p.SetWildcards([]string{"*.blumarkets.com"})

	resp := askProxy(t, port, buildQuery(t, "app.blumarkets.com."))
	if len(resp.Answers) != 1 {
		t.Fatalf("answer not relayed: %+v", resp)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		addrs, ok := learned["*.blumarkets.com|app.blumarkets.com"]
		mu.Unlock()
		if ok {
			if len(addrs) != 1 || addrs[0] != answer {
				t.Fatalf("learned wrong addrs: %v", addrs)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("learner never invoked")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A non-matching name is relayed but NOT learned.
	resp = askProxy(t, port, buildQuery(t, "example.org."))
	if len(resp.Answers) != 1 {
		t.Fatalf("non-matching answer not relayed: %+v", resp)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	n := len(learned)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("non-matching name was learned: %v", learned)
	}
}

func TestSetUpstreamsNormalizesAndGuardsSelfLoop(t *testing.T) {
	p := New(nil, nil)
	p.SetUpstreams([]string{"not-an-ip", "9.9.9.9", "1.1.1.1:5353"})
	p.mu.RLock()
	if len(p.upstreams) != 2 || p.upstreams[0] != "9.9.9.9:53" || p.upstreams[1] != "1.1.1.1:5353" {
		p.mu.RUnlock()
		t.Fatalf("upstreams = %v", p.upstreams)
	}
	p.mu.RUnlock()

	// The proxy's OWN address is the only loopback that gets skipped.
	port, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Stop)
	if !p.isSelf(net.JoinHostPort("127.0.0.1", itoa(port))) {
		t.Fatal("own address must be recognized as a self-loop")
	}
	if p.isSelf("127.0.0.1:53") {
		t.Fatal("a local resolver on :53 is a legitimate upstream")
	}
}

func TestAnswerStoreMergesAndRoundTrips(t *testing.T) {
	s := NewAnswerStore(8)
	a1 := netip.MustParseAddr("192.0.2.1")
	a2 := netip.MustParseAddr("192.0.2.2")

	if !s.Add("*.x.com", "a.x.com", []netip.Addr{a1}) {
		t.Fatal("first add should change")
	}
	if s.Add("*.x.com", "a.x.com", []netip.Addr{a1}) {
		t.Fatal("same answer should not change")
	}
	// A rotated answer merges rather than replaces (a pinned connection's route
	// must not flap away between lookups).
	if !s.Add("*.x.com", "a.x.com", []netip.Addr{a2}) {
		t.Fatal("new answer should merge")
	}
	if got := s.IPs("*.x.com"); len(got) != 2 {
		t.Fatalf("IPs = %v", got)
	}

	data, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	s2 := NewAnswerStore(8)
	if err := s2.Load(data); err != nil {
		t.Fatal(err)
	}
	if got := s2.IPs("*.x.com"); len(got) != 2 {
		t.Fatalf("round-trip lost data: %v", got)
	}
	if !s2.Prune([]string{}) {
		t.Fatal("prune of inactive rule should change")
	}
	if got := s2.IPs("*.x.com"); len(got) != 0 {
		t.Fatalf("prune left data: %v", got)
	}
}

// The name cap evicts the OLDEST name (not the newest) so a burst of junk
// lookups can never permanently freeze out a legitimate name.
func TestAnswerStoreEvictsOldestName(t *testing.T) {
	s := NewAnswerStore(2)
	base := time.Unix(1_700_000_000, 0)
	tick := 0
	s.SetClock(func() time.Time { tick++; return base.Add(time.Duration(tick) * time.Second) })
	ip := netip.MustParseAddr("192.0.2.9")

	s.Add("*.x.com", "old.x.com", []netip.Addr{ip})
	s.Add("*.x.com", "mid.x.com", []netip.Addr{ip})
	s.Add("*.x.com", "new.x.com", []netip.Addr{ip}) // evicts old.x.com

	if s.Names("*.x.com") != 2 {
		t.Fatalf("names = %d, want 2", s.Names("*.x.com"))
	}
	// The real (newest) name is learned; the oldest was dropped.
	if _, ok := s.m["*.x.com"]["new.x.com"]; !ok {
		t.Fatal("newest name must be present")
	}
	if _, ok := s.m["*.x.com"]["old.x.com"]; ok {
		t.Fatal("oldest name should have been evicted")
	}
}

// A learned address that isn't re-seen within the TTL expires — so a CDN
// wildcard doesn't accumulate dead IPs (and route table entries) forever.
func TestAnswerStoreExpiresStaleAddresses(t *testing.T) {
	s := NewAnswerStore(8)
	now := time.Unix(1_700_000_000, 0)
	s.SetClock(func() time.Time { return now })
	a1 := netip.MustParseAddr("192.0.2.1")
	a2 := netip.MustParseAddr("192.0.2.2")

	s.Add("*.cdn.com", "app.cdn.com", []netip.Addr{a1})
	now = now.Add(defaultAddrTTL / 2)
	s.Add("*.cdn.com", "app.cdn.com", []netip.Addr{a2}) // a1 still live, a2 fresh
	if got := s.IPs("*.cdn.com"); len(got) != 2 {
		t.Fatalf("both addrs should be live: %v", got)
	}
	now = now.Add(defaultAddrTTL/2 + time.Second) // a1 now past TTL, a2 still live
	if changed := s.GC(); !changed {
		t.Fatal("GC should have expired a1")
	}
	if got := s.IPs("*.cdn.com"); len(got) != 1 || got[0] != "192.0.2.2" {
		t.Fatalf("only the fresh addr should remain: %v", got)
	}
}

// Resolve queries the upstreams directly (bypassing the scoped resolver files),
// so the daemon can pre-warm wildcard subdomains itself — routing them before
// anything connects, regardless of how the browser resolves DNS.
func TestResolveDirectAgainstUpstream(t *testing.T) {
	answer := netip.MustParseAddr("81.91.145.166")
	up := fakeUpstream(t, answer)

	p := New(nil, nil)
	port, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Stop)
	_ = port
	p.SetUpstreams([]string{up})

	got := p.Resolve("app.blumarkets.com")
	if len(got) != 1 || got[0] != answer {
		t.Fatalf("Resolve = %v, want [%v]", got, answer)
	}

	// No upstream configured → no answer (never fabricates).
	p2 := New(nil, nil)
	if a := p2.Resolve("app.blumarkets.com"); len(a) != 0 {
		t.Fatalf("Resolve with no upstream = %v, want none", a)
	}
}

func TestCommonSubdomainLabelsNonEmpty(t *testing.T) {
	if len(CommonSubdomainLabels) < 20 {
		t.Fatalf("expected a substantial pre-warm wordlist, got %d labels", len(CommonSubdomainLabels))
	}
	seen := map[string]bool{}
	for _, l := range CommonSubdomainLabels {
		if seen[l] {
			t.Fatalf("duplicate label %q in the pre-warm list", l)
		}
		seen[l] = true
	}
}
