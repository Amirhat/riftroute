package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Amirhat/riftroute/internal/config"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/routing"
)

// Options wires a Manager into the daemon.
type Options struct {
	// Dir holds definitions (secrets) and runtime files; created 0700.
	Dir      string
	Launcher Launcher
	// Ifaces lists interfaces, to find a tunnel's by its assigned address.
	Ifaces func(ctx context.Context) ([]domain.Iface, error)
	// Resolve looks up a server host name (via: direct pins its addresses).
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// Apply installs the tunnels' current routes (Inputs) through the Apply
	// Protocol. Called at every transition that changes them.
	Apply func(ctx context.Context) error
	// OnChange is called after a status change (the daemon broadcasts state).
	OnChange func()
	Log      *slog.Logger
}

// Manager runs the daemon's tunnels: it stores their definitions, supervises
// one openvpn per connected tunnel through its management socket, and reports
// what the engine should route (Inputs).
type Manager struct {
	o      Options
	store  *defStore
	runDir string

	mu       sync.Mutex
	defs     map[string]*def
	profs    map[string]*Profile
	perrs    map[string]error
	rt       map[string]*live
	retrying bool
	closed   chan struct{}
}

type live struct {
	state   domain.TunnelState
	detail  string
	iface   string
	localIP string
	v6      bool
	server  string
	since   *time.Time
	lastErr string
	// tail is openvpn's last output lines from the previous session (the
	// live session's come from its process).
	tail    []string
	in, out uint64
	bypass  []netip.Addr
	sess    *session
}

type session struct {
	cancel   context.CancelFunc
	done     chan struct{}
	stopping atomic.Bool
	mgmt     atomic.Pointer[mgmtConn]
	proc     atomic.Value // Process
}

// New opens the definition store and cleans up after a previous daemon that
// died without stopping its tunnels.
func New(o Options) (*Manager, error) {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	st, err := openDefStore(o.Dir)
	if err != nil {
		return nil, err
	}
	m := &Manager{
		o: o, store: st, runDir: o.Dir,
		defs: map[string]*def{}, profs: map[string]*Profile{}, perrs: map[string]error{},
		rt: map[string]*live{}, closed: make(chan struct{}),
	}
	// A unix socket path is capped (~104 bytes on macOS); a long home
	// directory in dev can exceed it.
	if len(filepath.Join(o.Dir, strings.Repeat("x", 32)+".sock")) > 100 {
		if m.runDir, err = os.MkdirTemp("", "rr-tun-"); err != nil {
			return nil, err
		}
	}
	m.reapStale()
	defs, err := st.list()
	if err != nil {
		return nil, err
	}
	for _, d := range defs {
		m.cache(d)
	}
	return m, nil
}

func (m *Manager) cache(d *def) {
	m.defs[d.Name] = d
	p, err := Parse(d.Config)
	m.profs[d.Name], m.perrs[d.Name] = p, err
	if m.rt[d.Name] == nil {
		m.rt[d.Name] = &live{state: domain.TunnelDisconnected}
	}
}

// --- queries ---

// List returns every tunnel's status, sorted by name.
func (m *Manager) List() []domain.TunnelStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]domain.TunnelStatus, 0, len(m.defs))
	for _, d := range m.defs {
		out = append(out, m.statusLocked(d.Name))
	}
	slices.SortFunc(out, func(a, b domain.TunnelStatus) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// Status returns one tunnel's status.
func (m *Manager) Status(name string) (domain.TunnelStatus, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.defs[name] == nil {
		return domain.TunnelStatus{}, false
	}
	return m.statusLocked(name), true
}

func (m *Manager) statusLocked(name string) domain.TunnelStatus {
	d, p, r := m.defs[name], m.profs[name], m.rt[name]
	s := domain.TunnelStatus{
		Name: d.Name, Type: d.Type, Via: d.Via, Routes: append([]string{}, d.Routes...),
		AutoConnect: d.AutoConnect, Username: d.Username, HasPassword: d.Password != "",
		State: r.state, Detail: r.detail, Iface: r.iface, LocalIP: r.localIP, Server: r.server,
		Since: r.since, LastError: r.lastErr, BytesIn: r.in, BytesOut: r.out, Servers: []string{},
	}
	if p != nil {
		s.NeedsAuth, s.Servers, s.Ignored = p.NeedsAuth, p.Servers(), p.Ignored
	}
	if err := m.perrs[name]; err != nil && r.sess == nil {
		s.State, s.LastError = domain.TunnelFailed, "profile is no longer valid: "+err.Error()
	}
	return s
}

// Inputs is what the engine routes: for every tunnel with a live session, its
// server addresses (while pinned) and, once its interface is up, its
// destinations.
func (m *Manager) Inputs() []routing.TunnelInput {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []routing.TunnelInput
	for name, r := range m.rt {
		if r.sess == nil {
			continue
		}
		in := routing.TunnelInput{Name: name, V6: r.v6, Bypass: append([]netip.Addr(nil), r.bypass...)}
		if r.state == domain.TunnelConnected || r.state == domain.TunnelReconnecting {
			in.Iface = r.iface
		}
		if d := m.defs[name]; d != nil {
			in.Routes = append([]string(nil), d.Routes...)
		}
		out = append(out, in)
	}
	slices.SortFunc(out, func(a, b routing.TunnelInput) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// Log returns openvpn's recent output for a tunnel: the running session's,
// else the last one's. ok is false for an unknown tunnel.
func (m *Manager) Log(name string) ([]string, bool) {
	m.mu.Lock()
	r := m.rt[name]
	if r == nil {
		m.mu.Unlock()
		return nil, false
	}
	tail := append([]string(nil), r.tail...)
	s := r.sess
	m.mu.Unlock()
	if s != nil {
		if p, ok := s.proc.Load().(Process); ok {
			tail = p.Tail()
		}
	}
	return tail, true
}

// --- definitions ---

// ValidationError carries field-level problems with a submitted tunnel.
type ValidationError struct{ Issues []config.Issue }

func (e *ValidationError) Error() string {
	var ms []string
	for _, i := range e.Issues {
		ms = append(ms, i.Field+": "+i.Msg)
	}
	return "invalid tunnel: " + strings.Join(ms, "; ")
}

// Save creates or updates a tunnel. Config and Password left empty keep the
// stored values. A live tunnel whose connection settings changed reconnects;
// one whose routes changed re-applies them.
func (m *Manager) Save(ctx context.Context, spec domain.TunnelSpec) (domain.TunnelStatus, error) {
	var issues []config.Issue
	bad := func(field, msg string) {
		issues = append(issues, config.Issue{Severity: config.SevError, Field: field, Msg: msg})
	}
	spec.Name = strings.TrimSpace(spec.Name)
	if !ValidName(spec.Name) {
		bad("name", "use 1–32 lowercase letters, digits, - or _ (starting with a letter or digit)")
	}
	if spec.Type == "" {
		spec.Type = domain.TunnelOpenVPN
	}
	if spec.Type != domain.TunnelOpenVPN {
		bad("type", fmt.Sprintf("unsupported tunnel type %q (only openvpn)", spec.Type))
	}
	if spec.Via == "" {
		spec.Via = domain.TunnelViaDirect
	}
	if spec.Via != domain.TunnelViaDirect && spec.Via != domain.TunnelViaDefault {
		bad("via", fmt.Sprintf("via must be %q or %q", domain.TunnelViaDirect, domain.TunnelViaDefault))
	}
	routes, rerrs := normalizeRoutes(spec.Routes)
	for _, e := range rerrs {
		bad("routes", e)
	}
	if strings.ContainsAny(spec.Username+spec.Password, "\r\n\x00") {
		bad("username", "username and password can't contain line breaks")
	}

	m.mu.Lock()
	prev := m.defs[spec.Name]
	m.mu.Unlock()
	d := &def{
		Name: spec.Name, Type: spec.Type, Config: spec.Config, Username: spec.Username,
		Password: spec.Password, Via: spec.Via, Routes: routes, AutoConnect: spec.AutoConnect,
		UpdatedAt: time.Now(),
	}
	if prev != nil {
		if d.Config == "" {
			d.Config = prev.Config
		}
		if d.Username == "" {
			d.Username = prev.Username
		}
		if d.Password == "" {
			d.Password = prev.Password
		}
	}
	if strings.TrimSpace(d.Config) == "" {
		bad("config", "an OpenVPN profile (.ovpn) is required")
	} else if p, err := Parse(d.Config); err != nil {
		bad("config", err.Error())
	} else {
		if d.Username == "" {
			d.Username = p.InlineUser
		}
		if d.Password == "" {
			d.Password = p.InlinePass
		}
		if p.NeedsAuth && d.Username == "" {
			bad("username", "this profile logs in with a username and password; the username is required")
		}
		if p.NeedsAuth && d.Password == "" {
			bad("password", "this profile logs in with a username and password; the password is required")
		}
	}
	if len(issues) > 0 {
		return domain.TunnelStatus{}, &ValidationError{Issues: issues}
	}
	if err := m.store.put(d); err != nil {
		return domain.TunnelStatus{}, err
	}

	m.mu.Lock()
	m.cache(d)
	live := m.rt[d.Name].sess != nil
	m.mu.Unlock()
	switch {
	case live && prev != nil && (prev.Config != d.Config || prev.Username != d.Username ||
		prev.Password != d.Password || prev.Via != d.Via):
		if err := m.Disconnect(ctx, d.Name); err != nil {
			return domain.TunnelStatus{}, err
		}
		if err := m.Connect(d.Name); err != nil {
			return domain.TunnelStatus{}, err
		}
	case live:
		m.apply(ctx)
	}
	m.changed()
	st, _ := m.Status(d.Name)
	return st, nil
}

// Delete disconnects and removes a tunnel.
func (m *Manager) Delete(ctx context.Context, name string) error {
	m.mu.Lock()
	exists := m.defs[name] != nil
	m.mu.Unlock()
	if !exists {
		return fmt.Errorf("no tunnel named %q", name)
	}
	if err := m.Disconnect(ctx, name); err != nil {
		return err
	}
	if err := m.store.remove(name); err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.defs, name)
	delete(m.profs, name)
	delete(m.perrs, name)
	delete(m.rt, name)
	m.mu.Unlock()
	m.changed()
	return nil
}

func normalizeRoutes(in []string) ([]string, []string) {
	var out, errs []string
	seen := map[string]bool{}
	if len(in) > 256 {
		return nil, []string{"at most 256 routes per tunnel"}
	}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(v)
		if err != nil {
			a, aerr := netip.ParseAddr(v)
			if aerr != nil {
				errs = append(errs, fmt.Sprintf("%q is not an IP address or CIDR", v))
				continue
			}
			pfx = netip.PrefixFrom(a, a.BitLen())
		}
		if pfx.Bits() == 0 {
			errs = append(errs, fmt.Sprintf("%s would send ALL traffic into the tunnel; list the networks behind it instead", v))
			continue
		}
		s := pfx.Masked().String()
		if pfx.Bits() == pfx.Addr().BitLen() {
			s = pfx.Addr().String()
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out, errs
}

// --- connections ---

// Connect starts a tunnel (asynchronously; watch its status). Connecting a
// tunnel that is already up is a no-op.
func (m *Manager) Connect(name string) error {
	m.mu.Lock()
	d, p, perr := m.defs[name], m.profs[name], m.perrs[name]
	if d == nil {
		m.mu.Unlock()
		return fmt.Errorf("no tunnel named %q", name)
	}
	r := m.rt[name]
	if r.sess != nil {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()
	if perr != nil {
		return fmt.Errorf("tunnel %s: profile is no longer valid: %w", name, perr)
	}
	if p.NeedsAuth && (d.Username == "" || d.Password == "") {
		return fmt.Errorf("tunnel %s needs a username and password", name)
	}
	if err := m.o.Launcher.Check(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &session{cancel: cancel, done: make(chan struct{})}
	m.mu.Lock()
	// Re-read under the lock: a Delete (or a Save that replaced the
	// definition) may have run while it was released, and a session parked on
	// a forgotten entry would be an openvpn nothing can stop.
	r = m.rt[name]
	switch {
	case r == nil || m.defs[name] != d:
		m.mu.Unlock()
		cancel()
		return fmt.Errorf("tunnel %s changed while connecting; try again", name)
	case r.sess != nil: // lost a race with another Connect
		m.mu.Unlock()
		cancel()
		return nil
	}
	*r = live{state: domain.TunnelConnecting, detail: "starting", sess: s}
	m.mu.Unlock()
	m.changed()
	go m.run(ctx, name, d, p, s)
	return nil
}

// Disconnect stops a tunnel and waits for it to go down. Disconnecting a
// tunnel that isn't running clears a failed state.
func (m *Manager) Disconnect(ctx context.Context, name string) error {
	m.mu.Lock()
	r := m.rt[name]
	if r == nil {
		m.mu.Unlock()
		return fmt.Errorf("no tunnel named %q", name)
	}
	s := r.sess
	if s == nil {
		r.state, r.lastErr, r.detail = domain.TunnelDisconnected, "", ""
		m.mu.Unlock()
		m.changed()
		return nil
	}
	m.mu.Unlock()
	s.stopping.Store(true)
	if mc := s.mgmt.Load(); mc != nil {
		_ = mc.send("signal SIGTERM")
	} else {
		s.cancel() // not talking to openvpn yet: abort the setup
	}
	select {
	case <-s.done:
		return nil
	case <-time.After(10 * time.Second):
	case <-ctx.Done():
	}
	// openvpn didn't exit on SIGTERM: kill it.
	if p, ok := s.proc.Load().(Process); ok {
		_ = p.Kill()
	}
	s.cancel()
	select {
	case <-s.done:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("tunnel %s did not stop", name)
	}
}

// StartAuto connects every tunnel marked auto-connect (daemon startup).
func (m *Manager) StartAuto() {
	m.mu.Lock()
	var names []string
	for n, d := range m.defs {
		if d.AutoConnect {
			names = append(names, n)
		}
	}
	m.mu.Unlock()
	for _, n := range names {
		if err := m.Connect(n); err != nil {
			m.o.Log.Warn("tunnel auto-connect failed", "tunnel", n, "err", err)
			m.mu.Lock()
			m.rt[n].state, m.rt[n].lastErr = domain.TunnelFailed, err.Error()
			m.mu.Unlock()
		}
	}
}

// Shutdown stops every tunnel (daemon exit).
func (m *Manager) Shutdown() {
	select {
	case <-m.closed:
		return
	default:
		close(m.closed)
	}
	m.DisconnectAll()
}

// DisconnectAll stops every running tunnel (panic, shutdown).
func (m *Manager) DisconnectAll() {
	m.mu.Lock()
	var names []string
	for n, r := range m.rt {
		if r.sess != nil {
			names = append(names, n)
		}
	}
	m.mu.Unlock()
	var wg sync.WaitGroup
	for _, n := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			_ = m.Disconnect(ctx, n)
		}()
	}
	wg.Wait()
}

func (m *Manager) sockPath(name string) string { return filepath.Join(m.runDir, name+".sock") }
func (m *Manager) cfgPath(name string) string  { return filepath.Join(m.runDir, name+".ovpn") }
func (m *Manager) pidPath(name string) string  { return filepath.Join(m.runDir, name+".pid") }

// run is one connection attempt, from resolving the server to openvpn's exit.
func (m *Manager) run(ctx context.Context, name string, d *def, p *Profile, s *session) {
	defer close(s.done)
	defer m.finish(name, s)

	remotes, bypass, err := m.resolveRemotes(ctx, d.Via, p.Remotes)
	if err != nil {
		m.setErr(name, err.Error())
		return
	}
	m.update(name, func(r *live) { r.bypass, r.detail = bypass, "starting openvpn" })
	if len(bypass) > 0 {
		m.apply(ctx) // pin the server to the physical gateway before the first packet
	}

	sock, cfg := m.sockPath(name), m.cfgPath(name)
	_ = os.Remove(sock)
	if err := os.WriteFile(cfg, []byte(p.Render(RenderOptions{Remotes: remotes, Management: sock})), 0o600); err != nil {
		m.setErr(name, "write config: "+err.Error())
		return
	}
	proc, err := m.o.Launcher.Start(LaunchSpec{Name: name, Config: cfg, Management: sock, Profile: p})
	if err != nil {
		m.setErr(name, err.Error())
		return
	}
	s.proc.Store(proc)
	if proc.Pid() != os.Getpid() {
		_ = os.WriteFile(m.pidPath(name), []byte(strconv.Itoa(proc.Pid())), 0o600)
	}
	exited := make(chan struct{})
	go func() { _ = proc.Wait(); close(exited) }()

	dctx, dcancel := context.WithTimeout(ctx, 15*time.Second)
	mc, err := dialMgmt(dctx, sock)
	dcancel()
	if err != nil {
		_ = proc.Kill()
		<-exited
		m.setErr(name, "openvpn didn't start: "+lastLine(proc.Tail(), err.Error()))
		return
	}
	s.mgmt.Store(mc)
	go func() { // Disconnect before the socket was up, or setup aborted
		select {
		case <-ctx.Done():
			_ = mc.send("signal SIGTERM")
		case <-exited:
		}
	}()
	if s.stopping.Load() {
		_ = mc.send("signal SIGTERM")
	}
	for _, c := range []string{"state on", "bytecount 5", "hold release"} {
		_ = mc.send(c)
	}
	if d.Via == domain.TunnelViaDirect {
		go m.hintUnreachable(ctx, name, exited)
	}
	_ = mc.read(func(ev event) { m.handle(ctx, name, d, s, mc, ev) })
	_ = mc.close()

	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		_ = proc.Kill()
		<-exited
	}
	m.update(name, func(r *live) {
		if r.lastErr == "" && !s.stopping.Load() {
			r.lastErr = "openvpn exited: " + lastLine(proc.Tail(), "no output")
		}
	})
}

// handle reacts to one management notification.
func (m *Manager) handle(ctx context.Context, name string, d *def, s *session, mc *mgmtConn, ev event) {
	stop := func(msg string) {
		m.setErr(name, msg)
		_ = mc.send("signal SIGTERM")
	}
	switch ev.kind {
	case "STATE":
		st := parseState(ev.body)
		switch st.name {
		case "CONNECTED":
			iface := m.findIface(ctx, st.localIP)
			now := time.Now()
			m.update(name, func(r *live) {
				r.state, r.detail, r.lastErr = domain.TunnelConnected, "", ""
				if st.desc == "ERROR" {
					r.detail = "connected with errors"
				}
				r.iface, r.localIP, r.v6 = iface, st.localIP, st.localIPv6 != ""
				r.server = st.remoteIP
				if st.remotePort != "" {
					r.server += ":" + st.remotePort
				}
				r.since = &now
				if iface == "" {
					r.lastErr = fmt.Sprintf("connected, but no interface holds %s — routes not installed", st.localIP)
				}
			})
			m.apply(ctx)
		case "RECONNECTING":
			var tail []string
			if p, ok := s.proc.Load().(Process); ok {
				tail = p.Tail()
			}
			m.update(name, func(r *live) {
				r.state, r.detail = domain.TunnelReconnecting, st.desc
				if r.since == nil { // never got through: explain why, if openvpn's output says
					if why := diagnose(name, st.desc, tail); why != "" {
						r.lastErr = why
					}
				}
			})
		case "EXITING":
			m.update(name, func(r *live) {
				r.detail = st.desc
				if strings.Contains(st.desc, "auth-failure") && r.lastErr == "" {
					r.lastErr = "the server rejected the username or password"
				}
			})
		default:
			m.update(name, func(r *live) {
				if r.state != domain.TunnelReconnecting {
					r.state = domain.TunnelConnecting
				}
				r.detail = strings.ToLower(st.name)
			})
		}
		m.changed()
	case "PASSWORD":
		switch {
		case strings.HasPrefix(ev.body, "Need 'Auth'"):
			if d.Username == "" || d.Password == "" {
				stop("the server asks for a username and password, but none are saved")
				return
			}
			_ = mc.send(`username "Auth" ` + mgmtQuote(d.Username))
			_ = mc.send(`password "Auth" ` + mgmtQuote(d.Password))
		case strings.HasPrefix(ev.body, "Verification Failed"):
			m.setErr(name, "the server rejected the username or password")
		case strings.HasPrefix(ev.body, "Auth-Token"):
			// a session credential; never logged
		case strings.HasPrefix(ev.body, "Need 'Private Key'"):
			stop("the profile's private key is encrypted; RiftRoute can't unlock it yet")
		case strings.HasPrefix(ev.body, "Need"):
			stop("openvpn asked for a secret RiftRoute doesn't support: " + ev.body)
		}
	case "HOLD":
		// management-hold pauses openvpn at start AND at every restart
		// (ping-restart, …): release it each time.
		_ = mc.send("hold release")
	case "FATAL":
		m.setErr(name, ev.body)
	case "INFOMSG":
		if strings.HasPrefix(ev.body, "WEB_AUTH") || strings.HasPrefix(ev.body, "OPEN_URL") || strings.HasPrefix(ev.body, "CR_TEXT") {
			stop("this server needs a web or challenge login, which RiftRoute doesn't support yet")
		}
	case "NEED-OK", "NEED-STR":
		stop("openvpn asked a question RiftRoute can't answer: " + ev.body)
	case "BYTECOUNT":
		if in, out, ok := parseBytecount(ev.body); ok {
			m.update(name, func(r *live) { r.in, r.out = in, out })
		}
	case "ERROR":
		m.o.Log.Debug("openvpn management error", "tunnel", name, "msg", ev.body)
	}
}

// hintUnreachable explains a direct connection stuck before the server ever
// answered: typically another VPN's firewall (Windscribe's, …) drops traffic
// outside its tunnel, or the network can't reach the server at all.
func (m *Manager) hintUnreachable(ctx context.Context, name string, exited <-chan struct{}) {
	select {
	case <-ctx.Done():
		return
	case <-exited:
		return
	case <-time.After(25 * time.Second):
	}
	m.update(name, func(r *live) {
		stuck := r.detail == "tcp_connect" || r.detail == "wait" || r.detail == "resolve" || r.detail == "starting openvpn"
		if r.since == nil && r.lastErr == "" && stuck {
			r.lastErr = "can't reach the server directly — another VPN's firewall (e.g. Windscribe's) may be blocking " +
				"traffic outside its tunnel; allow the server there, or reach it through the main VPN (--via default)"
		}
	})
	m.changed()
}

// diagnose turns openvpn's output from a failed attempt into the likely cause
// and its fix, or "".
func diagnose(name, reason string, tail []string) string {
	attempt := tail
	for i := len(tail) - 1; i >= 0; i-- { // only this attempt's lines
		if strings.Contains(tail[i], "Initial packet from") {
			attempt = tail[i:]
			break
		}
	}
	has := func(sub string) bool {
		for _, l := range attempt {
			if strings.Contains(l, sub) {
				return true
			}
		}
		return false
	}
	switch {
	case has("VERIFY EKU ERROR"):
		return "the server's certificate isn't marked for TLS-server use, which the profile's `remote-cert-tls server` " +
			"requires (OpenVPN Connect doesn't check it) — replace that line with `remote-cert-ku` and " +
			"`verify-x509-name <server name> name`"
	case reason == "connection-reset" && has("VERIFY OK") && !has("Control Channel:"):
		return "the server hung up right after the login was sent — older OpenVPN servers do that for a wrong " +
			"username or password (re-enter it with `riftroute tunnel edit " + name + " --ask-password`), or when " +
			"none of the offered data ciphers is one they support (if the profile sets `data-ciphers`, include " +
			"the server's cipher, e.g. AES-256-CBC)"
	case reason == "ping-restart" || reason == "tls-error":
		return "the server answered, but the encrypted handshake never completed (" + reason +
			") — see `riftroute tunnel log " + name + "`"
	}
	return ""
}

// finish records the end of a session and withdraws its routes.
func (m *Manager) finish(name string, s *session) {
	m.mu.Lock()
	if r := m.rt[name]; r != nil && r.sess == s {
		r.sess, r.iface, r.bypass, r.detail = nil, "", nil, ""
		if p, ok := s.proc.Load().(Process); ok {
			r.tail = p.Tail()
		}
		r.in, r.out = 0, 0
		if s.stopping.Load() {
			r.state, r.lastErr, r.since = domain.TunnelDisconnected, "", nil
		} else {
			r.state = domain.TunnelFailed
			if r.lastErr == "" {
				r.lastErr = "the connection ended"
			}
		}
	}
	m.mu.Unlock()
	for _, f := range []string{m.sockPath(name), m.cfgPath(name), m.pidPath(name)} {
		_ = os.Remove(f)
	}
	s.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	m.apply(ctx)
	m.changed()
}

// resolveRemotes returns the remotes to hand openvpn and the addresses to pin
// to the physical gateway. via: direct resolves host names here, so the
// addresses openvpn dials are exactly the ones the bypass routes cover.
func (m *Manager) resolveRemotes(ctx context.Context, via domain.TunnelVia, rs []Remote) ([]Remote, []netip.Addr, error) {
	if via != domain.TunnelViaDirect {
		return rs, nil, nil
	}
	var out []Remote
	var pins []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, r := range rs {
		var addrs []netip.Addr
		if a, err := netip.ParseAddr(r.Host); err == nil {
			addrs = []netip.Addr{a}
		} else if m.o.Resolve != nil {
			rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			addrs, err = m.o.Resolve(rctx, r.Host)
			cancel()
			if err != nil {
				m.o.Log.Warn("tunnel server did not resolve", "host", r.Host, "err", err)
			}
		}
		for _, a := range addrs {
			a = a.Unmap()
			out = append(out, Remote{Host: a.String(), Port: r.Port, Proto: r.Proto})
			if !seen[a] {
				seen[a] = true
				pins = append(pins, a)
			}
		}
	}
	if len(out) == 0 {
		return nil, nil, errors.New("couldn't resolve any of the profile's servers")
	}
	// IPv4 first: openvpn tries remotes in order, and a v4 pin is the one a
	// v4-only network can honor.
	slices.SortStableFunc(out, func(a, b Remote) int {
		return cmpBool(IsAddr(a.Host) && netip.MustParseAddr(a.Host).Is4(), IsAddr(b.Host) && netip.MustParseAddr(b.Host).Is4())
	})
	return out, pins, nil
}

// findIface finds the interface holding ip (openvpn doesn't report its
// device name), waiting briefly for the address to appear.
func (m *Manager) findIface(ctx context.Context, ip string) string {
	want, err := netip.ParseAddr(ip)
	if err != nil || m.o.Ifaces == nil {
		return ""
	}
	for range 30 {
		ifs, _ := m.o.Ifaces(ctx)
		for _, ifc := range ifs {
			for _, a := range ifc.Addrs {
				if p, err := netip.ParsePrefix(a); err == nil && p.Addr() == want {
					return ifc.Name
				}
				if x, err := netip.ParseAddr(a); err == nil && x == want {
					return ifc.Name
				}
			}
		}
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(100 * time.Millisecond):
		}
	}
	return ""
}

func (m *Manager) update(name string, fn func(*live)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.rt[name]; r != nil {
		fn(r)
	}
}

func (m *Manager) setErr(name, msg string) {
	m.o.Log.Warn("tunnel error", "tunnel", name, "err", msg)
	m.update(name, func(r *live) { r.lastErr = msg })
	m.changed()
}

func (m *Manager) changed() {
	if m.o.OnChange != nil {
		m.o.OnChange()
	}
}

// apply installs the current tunnel routes. A failure (an interactive change
// awaiting confirmation blocks applies) is retried in the background.
func (m *Manager) apply(ctx context.Context) {
	if m.o.Apply == nil {
		return
	}
	err := m.o.Apply(ctx)
	if err == nil {
		return
	}
	m.o.Log.Warn("tunnel routes not applied yet; retrying", "err", err)
	m.mu.Lock()
	if m.retrying {
		m.mu.Unlock()
		return
	}
	m.retrying = true
	m.mu.Unlock()
	go func() {
		defer func() { m.mu.Lock(); m.retrying = false; m.mu.Unlock() }()
		for range 40 {
			select {
			case <-m.closed:
				return
			case <-time.After(3 * time.Second):
			}
			actx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := m.o.Apply(actx)
			cancel()
			if err == nil {
				return
			}
		}
	}()
}

// reapStale stops openvpn processes a previous daemon left running (it was
// killed before it could stop them) and clears their runtime files, so an
// auto-connect doesn't open a second session beside an orphan.
func (m *Manager) reapStale() {
	ents, err := os.ReadDir(m.runDir)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		switch {
		case strings.HasSuffix(n, ".pid"):
			data, _ := os.ReadFile(filepath.Join(m.runDir, n))
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 1 && m.isOurOpenVPN(pid) {
				m.o.Log.Info("stopping openvpn left by a previous daemon", "pid", pid)
				_ = terminate(pid)
				for i := 0; i < 30 && alive(pid); i++ {
					time.Sleep(100 * time.Millisecond)
				}
			}
			_ = os.Remove(filepath.Join(m.runDir, n))
		case strings.HasSuffix(n, ".sock"), strings.HasSuffix(n, ".ovpn"), strings.HasPrefix(n, ".tmp-"):
			_ = os.Remove(filepath.Join(m.runDir, n))
		}
	}
}

// isOurOpenVPN reports whether pid is an openvpn running a config from our
// run directory — so a recycled pid, or an openvpn the user started
// themselves, is never killed.
func (m *Manager) isOurOpenVPN(pid int) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ps", "-o", "args=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return false
	}
	args := strings.TrimSpace(string(out))
	bin, rest, _ := strings.Cut(args, " ")
	return filepath.Base(bin) == "openvpn" && strings.Contains(rest, "--config "+m.runDir+string(filepath.Separator))
}

// cmpBool orders true before false.
func cmpBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return -1
	}
	return 1
}

func lastLine(lines []string, fallback string) string {
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return fallback
}
