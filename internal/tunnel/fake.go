package tunnel

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/Amirhat/riftroute/internal/domain"
)

// FakeLauncher simulates openvpn for -provider fake and tests: it serves the
// real management protocol on the socket the config names, so the Manager's
// whole control path runs without root, a binary, or a server. The password
// "wrong" is rejected; anything else connects.
type FakeLauncher struct {
	Iface   string // interface the fake tunnel "creates" (default utun9)
	LocalIP string // address it is "assigned" (default 10.99.0.2)
	// OnUp/OnDown fire as the fake tunnel interface appears and goes away
	// (the daemon wires them to the fake provider's interface list).
	OnUp, OnDown func(iface, localIP string)
	// Missing makes Engine report a machine without openvpn (with this
	// machine's real install help).
	Missing bool
	// HangUp makes the server drop every attempt right after the login, the
	// way old servers answer a wrong password: openvpn reports RECONNECTING
	// (connection-reset) and, with the hold off, tries again on its own.
	HangUp bool
	// ExitAtStart makes openvpn exit before its management socket comes up
	// (a config it refused).
	ExitAtStart bool

	mu       sync.Mutex
	commands []string
	running  int
}

// Commands returns every management command the fake received, in order.
func (f *FakeLauncher) Commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.commands...)
}

// Running is the number of fake openvpn processes still alive.
func (f *FakeLauncher) Running() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

func (f *FakeLauncher) record(cmd string) {
	f.mu.Lock()
	f.commands = append(f.commands, cmd)
	f.mu.Unlock()
}

// Engine implements Launcher.
func (f *FakeLauncher) Engine() domain.TunnelEngine {
	if f.Missing {
		return detectEngine(readHost(), func() (string, os.FileInfo, error) { return "", nil, errNotFound }, nil)
	}
	return domain.TunnelEngine{Available: true, Path: "(fake)", Version: "2.6.0"}
}

// Start implements Launcher.
func (f *FakeLauncher) Start(spec LaunchSpec) (Process, error) {
	if e := f.Engine(); !e.Available {
		return nil, &EngineError{Engine: e}
	}
	if f.ExitAtStart {
		p := &fakeProcess{done: make(chan struct{})}
		p.logf("Options error: Unrecognized option or missing parameter(s)")
		p.exit()
		return p, nil
	}
	_ = os.Remove(spec.Management)
	ln, err := net.Listen("unix", spec.Management)
	if err != nil {
		return nil, err
	}
	iface, ip := f.Iface, f.LocalIP
	if iface == "" {
		iface = "utun9"
	}
	if ip == "" {
		ip = "10.99.0.2"
	}
	p := &fakeProcess{done: make(chan struct{}), ln: ln, f: f}
	f.mu.Lock()
	f.running++
	f.mu.Unlock()
	remote := Remote{Host: "203.0.113.1", Port: 1194}
	if len(spec.Profile.Remotes) > 0 {
		remote = spec.Profile.Remotes[0]
	}
	if cfg, err := os.ReadFile(spec.Config); err == nil {
		// The config carries the remotes actually in use (resolved/pinned).
		for _, l := range strings.Split(string(cfg), "\n") {
			var r Remote
			if n, _ := fmt.Sscanf(l, "remote %s %d %s", &r.Host, &r.Port, &r.Proto); n == 3 {
				remote = r
				break
			}
		}
	}
	go p.serve(spec.Profile.NeedsAuth, f.HangUp, iface, ip, remote, f.OnUp, f.OnDown)
	return p, nil
}

type fakeProcess struct {
	ln   net.Listener
	f    *FakeLauncher
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
	conn net.Conn
	tail []string
}

func (p *fakeProcess) Pid() int    { return os.Getpid() }
func (p *fakeProcess) Wait() error { <-p.done; return nil }

func (p *fakeProcess) Kill() error {
	p.exit()
	return nil
}

func (p *fakeProcess) Tail() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.tail...)
}

// exit ends the process: like a killed openvpn, its management connection
// closes with it.
func (p *fakeProcess) exit() {
	p.once.Do(func() {
		if p.ln != nil {
			_ = p.ln.Close()
		}
		p.mu.Lock()
		if p.conn != nil {
			_ = p.conn.Close()
		}
		p.mu.Unlock()
		if p.f != nil {
			p.f.mu.Lock()
			p.f.running--
			p.f.mu.Unlock()
		}
		close(p.done)
	})
}

func (p *fakeProcess) logf(format string, a ...any) {
	p.mu.Lock()
	p.tail = append(p.tail, fmt.Sprintf(format, a...))
	p.mu.Unlock()
}

func (p *fakeProcess) serve(needsAuth, hangUp bool, iface, ip string, remote Remote, onUp, onDown func(string, string)) {
	defer p.exit()
	c, err := p.ln.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	p.mu.Lock()
	p.conn = c
	p.mu.Unlock()
	var wmu sync.Mutex
	say := func(s string) {
		wmu.Lock()
		defer wmu.Unlock()
		_, _ = c.Write([]byte(s + "\n"))
	}
	state := func(name, desc, local string) {
		rip, rport := "", ""
		if name == "CONNECTED" {
			rip, rport = remote.Host, fmt.Sprint(remote.Port)
		}
		say(fmt.Sprintf(">STATE:1700000000,%s,%s,%s,%s,%s,,,", name, desc, local, rip, rport))
	}
	say(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info")
	say(">HOLD:Waiting for hold release:0")
	up := false
	connect := func() {
		state("GET_CONFIG", "", "")
		state("ASSIGN_IP", "", ip)
		if onUp != nil {
			onUp(iface, ip)
		}
		up = true
		p.logf("Initialization Sequence Completed")
		state("CONNECTED", "SUCCESS", ip)
	}
	down := func(reason string) {
		state("EXITING", reason, "")
		if up && onDown != nil {
			onDown(iface, ip)
		}
	}
	holding := true // management-hold: paused until released
	attempt := func() {
		state("WAIT", "", "")
		state("AUTH", "", "")
		if needsAuth {
			say(">PASSWORD:Need 'Auth' username/password")
		} else {
			connect()
		}
	}
	// restart is openvpn's SIGUSR1-style restart after a dropped attempt:
	// held again if the hold is still on, else straight into the next try.
	restart := func() {
		p.logf("Connection reset, restarting [0]")
		state("RECONNECTING", "connection-reset", "")
		if holding {
			say(">HOLD:Waiting for hold release:5")
			return
		}
		attempt()
	}
	holdOn := true
	var user string
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		cmd := strings.TrimSpace(sc.Text())
		if p.f != nil && cmd != "" {
			p.f.record(cmd)
		}
		switch {
		case cmd == "hold off":
			holdOn = false
			say("SUCCESS: hold flag set to OFF")
		case cmd == "hold release":
			say("SUCCESS: hold release succeeded")
			if !holding {
				continue // not paused: nothing to release
			}
			holding = false
			attempt()
		case strings.HasPrefix(cmd, `username "Auth" `):
			user = strings.TrimPrefix(cmd, `username "Auth" `)
			say("SUCCESS: 'Auth' username entered, but not yet verified")
		case strings.HasPrefix(cmd, `password "Auth" `):
			say("SUCCESS: 'Auth' password entered, but not yet verified")
			if user == "" || strings.TrimPrefix(cmd, `password "Auth" `) == `"wrong"` {
				say(">PASSWORD:Verification Failed: 'Auth'")
				p.logf("AUTH: Received control message: AUTH_FAILED")
				down("auth-failure")
				return
			}
			if hangUp {
				holding = holdOn
				restart()
				continue
			}
			connect()
		case cmd == "signal SIGTERM":
			say("SUCCESS: signal SIGTERM thrown")
			down("SIGTERM")
			return
		case cmd == "":
		default:
			say("SUCCESS: " + cmd)
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, net.ErrClosed) {
		p.logf("management: %v", err)
	}
}
