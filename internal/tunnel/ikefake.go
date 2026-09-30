package tunnel

import (
	"context"
	"io/fs"
	"net/netip"
	"os"
	"sync"

	"github.com/Amirhat/riftroute/internal/domain"
)

// FakeIKE simulates charon-cmd for -provider fake and tests: no process, no
// socket, no interface — the connection is up as soon as it's started, with
// VIP on Iface (which OnUp announces).
type FakeIKE struct {
	Iface string // the TUN it "creates" (default utun8)
	VIP   string // the address the server "assigns" (default 10.98.0.2); "none" for none
	// OnUp/OnDown fire as the fake interface gets its address and goes
	// away (the daemon wires them to the fake provider's interface list).
	OnUp, OnDown func(iface, vip string)
	// Missing makes Engine report a machine without charon-cmd (with this
	// machine's real install help).
	Missing bool
	// Fail: every attempt exits at once, having printed these lines.
	Fail []string

	mu    sync.Mutex
	specs []IKESpec
	live  []*fakeIKEProcess
}

// Engine implements IKELauncher.
func (f *FakeIKE) Engine() domain.TunnelEngine {
	if f.Missing {
		return detectIKEEngine(readHost(), func() (string, fs.FileInfo, error) { return "", nil, errNotFound }, nil)
	}
	return domain.TunnelEngine{Available: true, Path: "(fake)", Version: "6.1.0"}
}

// Start implements IKELauncher.
func (f *FakeIKE) Start(spec IKESpec) (IKEProcess, error) {
	if e := f.Engine(); !e.Available {
		return nil, &EngineError{Engine: e}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.specs = append(f.specs, spec)
	p := &fakeIKEProcess{f: f, done: make(chan struct{}), iface: f.Iface, up: true}
	if p.iface == "" {
		p.iface = "utun8"
	}
	switch f.VIP {
	case "":
		p.vip = netip.MustParseAddr("10.98.0.2")
	case "none":
	default:
		p.vip = netip.MustParseAddr(f.VIP)
	}
	p.log("Starting charon-cmd IKE client (strongSwan 6.1.0, fake)")
	if len(f.Fail) > 0 {
		for _, l := range f.Fail {
			p.log(l)
		}
		p.closeLocked()
		return p, nil
	}
	f.live = append(f.live, p)
	if p.vip.IsValid() && f.OnUp != nil {
		p.announced = true
		f.OnUp(p.iface, p.vip.String())
	}
	return p, nil
}

// Started returns every session the fake was asked to start, in order.
func (f *FakeIKE) Started() []IKESpec {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]IKESpec(nil), f.specs...)
}

// Running is the number of fake charon-cmds still running.
func (f *FakeIKE) Running() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.live)
}

// Drop makes every running connection drop, the way a dead server's does:
// charon-cmd keeps running without it.
func (f *FakeIKE) Drop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.live {
		p.up = false
		p.log("giving up after 5 retransmits")
	}
}

type fakeIKEProcess struct {
	f     *FakeIKE
	done  chan struct{}
	iface string
	vip   netip.Addr
	// under f.mu:
	up, announced, gone bool
	tail                []string
}

func (p *fakeIKEProcess) Pid() int    { return os.Getpid() }
func (p *fakeIKEProcess) Wait() error { <-p.done; return nil }
func (p *fakeIKEProcess) Kill() error { p.exit(); return nil }
func (p *fakeIKEProcess) Stop() error {
	p.f.mu.Lock()
	p.log("SIGTERM received, shutting down")
	p.f.mu.Unlock()
	p.exit()
	return nil
}

func (p *fakeIKEProcess) Tail() []string {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	return append([]string(nil), p.tail...)
}

func (p *fakeIKEProcess) Status(context.Context) (IKEStatus, error) {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	if p.gone {
		return IKEStatus{}, errIKENotRunning
	}
	if !p.up {
		return IKEStatus{State: "CONNECTING"}, nil
	}
	st := IKEStatus{State: "ESTABLISHED", Up: true, Server: netip.MustParseAddrPort("192.0.2.44:4500"), In: 100, Out: 50}
	if p.vip.IsValid() {
		st.VIPs = []netip.Addr{p.vip}
	}
	return st, nil
}

func (p *fakeIKEProcess) log(l string) { p.tail = append(p.tail, l) } // under f.mu

func (p *fakeIKEProcess) exit() {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	p.closeLocked()
}

func (p *fakeIKEProcess) closeLocked() {
	if p.gone {
		return
	}
	p.gone = true
	for i, q := range p.f.live {
		if q == p {
			p.f.live = append(p.f.live[:i], p.f.live[i+1:]...)
			break
		}
	}
	if p.announced && p.f.OnDown != nil {
		p.f.OnDown(p.iface, p.vip.String())
	}
	close(p.done)
}
