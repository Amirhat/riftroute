package safety

import (
	"context"
	"net"
	"sync"
	"time"
)

// Prober tests reachability of a connectivity anchor (gateway or canary). The
// watchdog uses it to decide whether a change broke connectivity (spec §2.1).
type Prober interface {
	Probe(ctx context.Context, anchor string) bool
}

// DialProber treats an anchor as reachable if a short TCP connection to it
// succeeds (defaults to port 443). It does not require root, unlike ICMP, and is
// a fine connectivity proxy for the deadman switch.
type DialProber struct {
	Port    string
	Timeout time.Duration
}

func (p DialProber) Probe(ctx context.Context, anchor string) bool {
	port := p.Port
	if port == "" {
		port = "443"
	}
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(cctx, "tcp", net.JoinHostPort(anchor, port))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// FakeProber is a controllable prober for tests. Unknown anchors are reachable
// until SetReachable marks them otherwise.
type FakeProber struct {
	mu    sync.Mutex
	state map[string]bool
}

// NewFakeProber returns a prober where all anchors are initially reachable.
func NewFakeProber() *FakeProber { return &FakeProber{state: map[string]bool{}} }

// SetReachable flips an anchor's reachability.
func (p *FakeProber) SetReachable(anchor string, reachable bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state[anchor] = reachable
}

func (p *FakeProber) Probe(_ context.Context, anchor string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if v, ok := p.state[anchor]; ok {
		return v
	}
	return true
}
