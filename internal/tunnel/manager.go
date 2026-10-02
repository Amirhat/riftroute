package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Amirhat/riftroute/internal/config"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/routing"
	"github.com/Amirhat/riftroute/internal/telemetry"
)

// Options wires a Manager into the daemon.
type Options struct {
	// Dir holds definitions (secrets) and runtime files; created 0700.
	Dir      string
	Launcher Launcher
	// Ifaces lists interfaces, to find a tunnel's by its assigned address.
	Ifaces func(ctx context.Context) ([]domain.Iface, error)
	// Routes lists the kernel's routes (both families), to check what a
	// connection added on its own; nil skips that check.
	Routes func(ctx context.Context) ([]domain.Route, error)
	// Protected are addresses no tunnel's own addressing may cover (the
	// physical gateways, the resolvers in use, the watchdog's anchors).
	Protected func(ctx context.Context) []netip.Addr
	// Resolve looks up a server host name (via: direct pins its addresses).
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// Apply installs the tunnels' current routes (Inputs) through the Apply
	// Protocol. Called at every transition that changes them.
	Apply func(ctx context.Context) error
	// OnChange is called after a status change (the daemon broadcasts state).
	OnChange func()
	// Count counts a telemetry event (telemetry.Counters.Inc): sessions
	// connected, dropped, given up, failed attempts by cause. nil: none.
	Count func(key string)
	// WireGuard makes WireGuard's tun devices; nil is this OS's own.
	WireGuard WGSystem
	// IKE starts IKEv2 sessions (charon-cmd); nil: IKEv2 tunnels don't
	// connect.
	IKE IKELauncher
	// Owned reads the routes RiftRoute owns (the ownership map). A tunnel's
	// own — tagged tunnel:<name>, on-link — include what tunnel-mode
	// profiles send into it, which only the engine knows: on macOS they stay
	// on the tunnel's interface across an openvpn restart, untagged, and
	// mustn't be taken for routes the server pushed. nil: none.
	Owned func() []domain.ManagedRoute
	Log   *slog.Logger
}

// Manager runs the daemon's tunnels: it stores their definitions, runs one
// session per connected tunnel through its protocol's driver (driver.go), and
// reports what the engine should route (Inputs).
type Manager struct {
	o       Options
	store   *defStore
	runDir  string
	drivers map[domain.TunnelType]driver

	ap *applier

	mu     sync.Mutex
	defs   map[string]*def
	parsed map[string]*parsed
	perrs  map[string]error
	rt     map[string]*live
	// broken are saved definitions that can't be read: listed as failed, so
	// the user sees them and can delete them.
	broken map[string]error
	// resume are the tunnels the previous run asked to bring back
	// (RememberForRestart), until StartAuto does; restarting are the ones
	// this run will bring back after its own restart. Both stay wanted
	// while they're down, so a block-mode one keeps blocking.
	resume, restarting map[string]bool
	// seen is what observe saw of each tunnel last (telemetry).
	seen map[string]seen
	// logins are the fingerprints of the logins that last connected, by
	// tunnel (kept in the definitions' directory too; see loginPath).
	loginMu sync.Mutex
	logins  map[string]string
	closed  chan struct{}
	shut    sync.Once
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
	// servers are the addresses openvpn may connect to (the pins for via
	// direct; resolved here, best-effort, for via default), so the engine
	// never routes the tunnel's own server into it.
	servers []netip.Addr
	sess    *session
	// deleting refuses new connections while Delete tears the tunnel down.
	deleting bool
	// failures counts attempts that ended before connecting, since the last
	// successful connection (or the start of the session).
	failures int
	// want: someone asked for the tunnel to be up (Connect, auto-connect, a
	// resume) and nobody has taken it down since (Disconnect, a panic,
	// Delete). A session that ends on its own leaves it set. While it's
	// set and the tunnel isn't connected, a block-mode tunnel refuses its
	// destinations.
	want bool
}

type session struct {
	cancel   context.CancelFunc
	done     chan struct{}
	stopping atomic.Bool
	mgmt     atomic.Pointer[mgmtConn]
	proc     atomic.Value // Process
	released atomic.Bool  // the first management hold was released
	resolved atomic.Int64 // unix time of the last server re-resolve
}

// shutdownApplyWait bounds how long Shutdown waits for the tunnels' routes
// to be withdrawn.
var shutdownApplyWait = 5 * time.Second

// How long a stop waits for openvpn to exit after SIGTERM, then after
// SIGKILL. Shutdown stops every tunnel at once, and the whole stop — these,
// shutdownApplyWait, resolving pending route changes — has to fit in the
// service manager's stop timeout (launchd: ExitTimeOut, 20 s on installs
// from before it was raised).
var stopGrace, killGrace = 6 * time.Second, 3 * time.Second

// Connection attempt limits.
var (
	// maxFailedAttempts: a tunnel that has never connected in this session
	// gives up after this many failed attempts, rather than retrying a
	// rejected login (or a server that hangs up after it) until the account
	// is locked out.
	maxFailedAttempts = 6
	// reresolveAfter: a tunnel that was up and has failed this many
	// reconnects in a row looks its servers' names up again (their
	// addresses may have moved; openvpn only knows the pinned ones).
	reresolveAfter = 3
	// holdBackoff bounds the pause before releasing a management hold after
	// the first: openvpn's own connect-retry backoff when it reports one.
	holdBackoffMin, holdBackoffMax = 2 * time.Second, 5 * time.Minute
)

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
		defs: map[string]*def{}, parsed: map[string]*parsed{}, perrs: map[string]error{},
		rt: map[string]*live{}, broken: map[string]error{}, closed: make(chan struct{}),
	}
	m.drivers = map[domain.TunnelType]driver{
		domain.TunnelOpenVPN:   ovpnDriver{o: &m.o},
		domain.TunnelWireGuard: wgDriver{o: &m.o},
		domain.TunnelIKEv2:     ikev2Driver{o: &m.o},
	}
	m.ap = newApplier(func(ctx context.Context) error {
		if m.o.Apply == nil {
			return nil
		}
		return m.o.Apply(ctx)
	}, o.Log)
	// A unix socket path is capped (~104 bytes on macOS); a long home
	// directory in dev can exceed it. The fallback is stable per definitions
	// directory, so the next start still finds (and reaps) what this one ran.
	if len(filepath.Join(o.Dir, strings.Repeat("x", 32)+".sock")) > 100 {
		if m.runDir, err = shortRunDir(o.Dir); err != nil {
			// Tunnels still run; only a crashed run's leftovers go unreaped.
			o.Log.Warn("no stable run directory for tunnels; using a temporary one", "err", err)
			if m.runDir, err = os.MkdirTemp("", "rr-tun-"); err != nil {
				return nil, err
			}
		}
	}
	m.reapStale()
	defs, broken, err := st.scan()
	if err != nil {
		return nil, err
	}
	for _, d := range defs {
		m.cache(d)
	}
	for name, err := range broken {
		o.Log.Warn("tunnel definition unreadable; skipped", "tunnel", name, "err", err)
		m.broken[name] = err
	}
	// The tunnels StartAuto will bring up are wanted from the start: the
	// first apply (the startup Resync) must not withdraw a block the
	// previous run left for them, only for StartAuto to put it back.
	m.resume = m.takeResume()
	for n, d := range m.defs {
		if d.AutoConnect || m.resume[n] {
			m.rt[n].want = true
		}
	}
	return m, nil
}

// parse reads a config with its type's driver.
func (m *Manager) parse(t domain.TunnelType, config string) (*parsed, error) {
	drv := m.drivers[t]
	if drv == nil {
		return nil, fmt.Errorf("unsupported tunnel type %q", t)
	}
	return drv.parse(config)
}

// typeNames lists the supported tunnel types, for messages.
func (m *Manager) typeNames() string {
	var ts []string
	for t := range m.drivers {
		ts = append(ts, string(t))
	}
	slices.Sort(ts)
	return strings.Join(ts, ", ")
}

// shortRunDir is a private directory under the system temp dir named after
// dir: created 0700, and refused if it exists as anything but a directory of
// ours that only we can use.
func shortRunDir(dir string) (string, error) {
	sum := sha256.Sum256([]byte(dir))
	p := filepath.Join(os.TempDir(), "rr-tun-"+hex.EncodeToString(sum[:6]))
	if err := os.Mkdir(p, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 || !ownedByUs(fi) {
		return "", fmt.Errorf("%s isn't a private directory of this user; remove it", p)
	}
	return p, nil
}

func (m *Manager) cache(d *def) {
	m.defs[d.Name] = d
	p, err := m.parse(d.Type, d.Config)
	m.parsed[d.Name], m.perrs[d.Name] = p, err
	if m.rt[d.Name] == nil {
		m.rt[d.Name] = &live{state: domain.TunnelDisconnected}
	}
}

// --- queries ---

// List returns every tunnel's status, sorted by name.
func (m *Manager) List() []domain.TunnelStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]domain.TunnelStatus, 0, len(m.defs)+len(m.broken))
	for _, d := range m.defs {
		out = append(out, m.statusLocked(d.Name))
	}
	for name, err := range m.broken {
		out = append(out, brokenStatus(name, err))
	}
	slices.SortFunc(out, func(a, b domain.TunnelStatus) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// Status returns one tunnel's status.
func (m *Manager) Status(name string) (domain.TunnelStatus, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err, ok := m.broken[name]; ok {
		return brokenStatus(name, err), true
	}
	if m.defs[name] == nil {
		return domain.TunnelStatus{}, false
	}
	return m.statusLocked(name), true
}

func brokenStatus(name string, err error) domain.TunnelStatus {
	return domain.TunnelStatus{
		Name: name, Type: domain.TunnelOpenVPN, Via: domain.TunnelViaDirect, Unreadable: true,
		State: domain.TunnelFailed, Routes: []string{}, Servers: []string{},
		LastError: "its saved definition can't be read (" + err.Error() + "); delete it and add it again",
	}
}

func (m *Manager) statusLocked(name string) domain.TunnelStatus {
	d, p, r := m.defs[name], m.parsed[name], m.rt[name]
	s := domain.TunnelStatus{
		Name: d.Name, Type: d.Type, Via: d.Via, Routes: append([]string{}, d.Routes...),
		AutoConnect: d.AutoConnect, WhenDown: whenDown(d), Blocking: blocking(d, r),
		Username: d.Username, HasPassword: d.Password != "",
		State: r.state, Detail: r.detail, Iface: r.iface, LocalIP: r.localIP, Server: r.server,
		Since: r.since, LastError: r.lastErr, BytesIn: r.in, BytesOut: r.out, Servers: []string{},
	}
	if p != nil {
		s.NeedsAuth, s.Servers, s.Ignored = p.needsAuth, p.servers, p.ignored
		if p.needsAuth {
			// A login the profile carries (an IKEv2 one saved before its
			// username and password were kept with the tunnel).
			s.Username, s.HasPassword = orString(s.Username, p.inlineUser), s.HasPassword || p.inlinePass != ""
		}
		if p.ike != nil && !p.ike.CertExpires().IsZero() {
			exp := p.ike.CertExpires()
			s.CertExpires = &exp
		}
	}
	if err := m.perrs[name]; err != nil && r.sess == nil {
		s.State, s.LastError = domain.TunnelFailed, "profile is no longer valid: "+err.Error()
	}
	return s
}

// Inputs is what the engine routes: for every tunnel with a live session, its
// server addresses (while pinned) and, while it's connected, its
// destinations; and every block-mode tunnel that's wanted, so its
// destinations are refused while it isn't connected (Block).
func (m *Manager) Inputs() []routing.TunnelInput {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []routing.TunnelInput
	for name, r := range m.rt {
		d := m.defs[name]
		block := d.blocks() && r.want
		if r.sess == nil && !block {
			continue
		}
		in := routing.TunnelInput{Name: name, V6: r.v6, Block: block, Bypass: append([]netip.Addr(nil), r.bypass...),
			Servers: append([]netip.Addr(nil), r.servers...)}
		if r.sess == nil {
			// No session to say where it connects: the last one's
			// addresses and the config's own, so no reject route holds
			// the server it'll need when it's connected again.
			in.Servers = addAddrs(in.Servers, configServers(m.parsed[name])...)
		}
		// Into the tunnel only while it's connected: a reconnecting one
		// keeps its interface (persist-tun; WireGuard's device lives with
		// the session), but traffic into it goes nowhere.
		if r.sess != nil && r.state == domain.TunnelConnected {
			in.Iface = r.iface
		}
		if d != nil {
			in.Routes = append([]string(nil), d.Routes...)
		}
		out = append(out, in)
	}
	slices.SortFunc(out, func(a, b routing.TunnelInput) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// whenDown is a definition's setting, fallback when unset.
func whenDown(d *def) domain.TunnelWhenDown {
	if d.blocks() {
		return domain.TunnelBlock
	}
	return domain.TunnelFallback
}

// blocking reports whether a tunnel refuses its destinations now: set to
// block, wanted, and not connected.
func blocking(d *def, r *live) bool {
	return d.blocks() && r.want && (r.sess == nil || r.state != domain.TunnelConnected)
}

// configServers are the literal server addresses in a tunnel's config.
func configServers(p *parsed) []netip.Addr {
	if p == nil {
		return nil
	}
	var out []netip.Addr
	for _, rm := range p.remotes {
		if a, err := netip.ParseAddr(rm.Host); err == nil {
			out = addAddrs(out, a.Unmap())
		}
	}
	return out
}

// addAddrs appends the addresses as isn't already there.
func addAddrs(to []netip.Addr, as ...netip.Addr) []netip.Addr {
	for _, a := range as {
		if !slices.Contains(to, a) {
			to = append(to, a)
		}
	}
	return to
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
		// A client that doesn't send the type (one from before WireGuard)
		// edits a tunnel of the type it has.
		spec.Type = domain.TunnelOpenVPN
		m.mu.Lock()
		if prev := m.defs[spec.Name]; prev != nil && prev.Type != "" {
			spec.Type = prev.Type
		}
		m.mu.Unlock()
	}
	if m.drivers[spec.Type] == nil {
		bad("type", fmt.Sprintf("unsupported tunnel type %q (%s)", spec.Type, m.typeNames()))
	}
	if spec.Via == "" {
		spec.Via = domain.TunnelViaDirect
	}
	if spec.Via != domain.TunnelViaDirect && spec.Via != domain.TunnelViaDefault {
		bad("via", fmt.Sprintf("via must be %q or %q", domain.TunnelViaDirect, domain.TunnelViaDefault))
	}
	switch spec.WhenDown {
	case "", domain.TunnelFallback, domain.TunnelBlock:
	default:
		bad("when_down", fmt.Sprintf("when_down must be %q or %q", domain.TunnelFallback, domain.TunnelBlock))
	}
	routes, rerrs := normalizeRoutes(spec.Routes)
	for _, e := range rerrs {
		bad("routes", e)
	}
	if strings.ContainsAny(spec.Username+spec.Password, "\r\n\x00") {
		bad("username", "username and password can't contain line breaks")
	}
	if spec.Type == domain.TunnelWireGuard && (spec.Username != "" || spec.Password != "") {
		bad("username", "a WireGuard tunnel has no username or password; its keys are in the configuration")
	}

	m.mu.Lock()
	prev := m.defs[spec.Name]
	deleting := m.rt[spec.Name] != nil && m.rt[spec.Name].deleting
	m.mu.Unlock()
	if deleting {
		return domain.TunnelStatus{}, fmt.Errorf("tunnel %s is being deleted; try again", spec.Name)
	}
	d := &def{
		Name: spec.Name, Type: spec.Type, Config: spec.Config, Username: spec.Username,
		Password: spec.Password, Via: spec.Via, Routes: routes, AutoConnect: spec.AutoConnect,
		WhenDown: spec.WhenDown, UpdatedAt: time.Now(),
	}
	if d.WhenDown == "" && prev != nil {
		d.WhenDown = prev.WhenDown // a client from before the setting keeps it
	}
	if d.WhenDown == domain.TunnelFallback {
		d.WhenDown = "" // the default, stored as a definition from before it
	}
	keptPassword := false
	if prev != nil && prev.Type == d.Type {
		if d.Config == "" {
			d.Config = prev.Config
		}
		if d.Username == "" {
			d.Username = prev.Username
		}
		if d.Password == "" && prev.Password != "" {
			d.Password, keptPassword = prev.Password, true
		}
	}
	if strings.TrimSpace(d.Config) == "" {
		if d.Type == domain.TunnelWireGuard {
			bad("config", "a WireGuard configuration (.conf) is required")
		} else if d.Type == domain.TunnelIKEv2 {
			bad("config", "a configuration profile (.mobileconfig) is required")
		} else {
			bad("config", "an OpenVPN profile (.ovpn) is required")
		}
	} else if m.drivers[d.Type] == nil {
		// reported above
	} else if p, err := m.parse(d.Type, d.Config); err != nil {
		bad("config", err.Error())
	} else {
		// A saved password goes only to the profile it was entered for:
		// replacing the profile needs it typed again. Otherwise anyone who may
		// edit tunnels could have it sent to a server of their choosing — or
		// to the same server name, trusted through a different CA or without
		// its name check.
		if keptPassword && prev.Config != d.Config {
			d.Password = ""
			if p.needsAuth && p.inlinePass == "" {
				bad("password", "the profile changed; enter the password again")
			}
		}
		if d.Username == "" {
			d.Username = p.inlineUser
		}
		if d.Password == "" {
			d.Password = p.inlinePass
		}
		if d.Type == domain.TunnelIKEv2 && !p.needsAuth && (spec.Username != "" || spec.Password != "") {
			bad("username", "this profile logs in with "+ikeLoginName(p.ike.Auth)+"; it takes no username or password")
		}
		if p.needsAuth && d.Username == "" {
			bad("username", "this profile logs in with a username and password; the username is required")
		}
		if p.needsAuth && d.Password == "" {
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
	delete(m.broken, d.Name) // a new definition replaces an unreadable one
	m.cache(d)
	running := m.rt[d.Name].sess != nil
	wanted := m.rt[d.Name].want
	m.mu.Unlock()
	switch {
	case running && prev != nil && (prev.Config != d.Config || prev.Username != d.Username ||
		prev.Password != d.Password || prev.Via != d.Via):
		// Reconnect; still wanted meanwhile, so a block-mode tunnel keeps
		// blocking.
		if err := m.stop(ctx, d.Name, true); err != nil {
			return domain.TunnelStatus{}, err
		}
		if err := m.Connect(d.Name); err != nil {
			m.update(d.Name, func(r *live) {
				if r.sess == nil {
					r.state, r.lastErr = domain.TunnelFailed, err.Error()
				}
			})
			m.changed()
			return domain.TunnelStatus{}, err
		}
	case running || wanted:
		// Its routes (or what it does while down) may have changed.
		_ = m.applyAndWait(ctx, 10*time.Second)
	}
	m.changed()
	st, _ := m.Status(d.Name)
	return st, nil
}

// Delete disconnects and removes a tunnel. From its first step on, no new
// connection can start: one that slipped in between the disconnect and the
// removal would be an openvpn nothing tracks.
func (m *Manager) Delete(ctx context.Context, name string) error {
	m.mu.Lock()
	if _, ok := m.broken[name]; ok {
		delete(m.broken, name)
		m.mu.Unlock()
		if err := m.store.remove(name); err != nil {
			return err
		}
		m.forgetLogin(name)
		m.changed()
		return nil
	}
	r := m.rt[name]
	if m.defs[name] == nil || r == nil {
		m.mu.Unlock()
		return fmt.Errorf("no tunnel named %q", name)
	}
	if r.deleting {
		m.mu.Unlock()
		return fmt.Errorf("tunnel %s is already being deleted", name)
	}
	r.deleting = true
	m.mu.Unlock()
	undo := func() { m.update(name, func(r *live) { r.deleting = false }) }
	if err := m.Disconnect(ctx, name); err != nil {
		undo()
		return err
	}
	if err := m.store.remove(name); err != nil {
		undo()
		return err
	}
	m.forgetLogin(name)
	m.mu.Lock()
	delete(m.defs, name)
	delete(m.parsed, name)
	delete(m.perrs, name)
	delete(m.rt, name)
	m.mu.Unlock()
	m.changed()
	return nil
}

// routePrefix parses a normalized route (a CIDR, or an address for a host).
func routePrefix(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
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
	d, p, perr := m.defs[name], m.parsed[name], m.perrs[name]
	if _, bad := m.broken[name]; bad {
		m.mu.Unlock()
		return fmt.Errorf("tunnel %s's saved definition can't be read; delete it and add it again", name)
	}
	if d == nil {
		m.mu.Unlock()
		return fmt.Errorf("no tunnel named %q", name)
	}
	r := m.rt[name]
	if r.deleting {
		m.mu.Unlock()
		return fmt.Errorf("tunnel %s is being deleted", name)
	}
	if r.sess != nil {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()
	if perr != nil {
		return fmt.Errorf("tunnel %s: profile is no longer valid: %w", name, perr)
	}
	if p.needsAuth && (orString(d.Username, p.inlineUser) == "" || orString(d.Password, p.inlinePass) == "") {
		return fmt.Errorf("tunnel %s needs a username and password", name)
	}
	drv := m.drivers[d.Type]
	if c, ok := drv.(interface{ check(*parsed) error }); ok {
		if err := c.check(p); err != nil {
			return fmt.Errorf("tunnel %s: %w", name, err)
		}
	}
	if e := drv.engine(); !e.Available {
		if m.o.Count != nil {
			typ := d.Type
			if typ == "" {
				typ = domain.TunnelOpenVPN
			}
			m.o.Count(telemetry.FailureKey(string(typ), "engine"))
		}
		return &EngineError{Engine: e}
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &session{cancel: cancel, done: make(chan struct{})}
	m.mu.Lock()
	// Re-read under the lock: a Delete (or a Save that replaced the
	// definition) may have run while it was released, and a session parked on
	// a forgotten entry would be an openvpn nothing can stop.
	r = m.rt[name]
	switch {
	case m.isClosed(): // checked under the lock DisconnectAll scans with
		m.mu.Unlock()
		cancel()
		return errShuttingDown
	case r == nil || m.defs[name] != d || r.deleting:
		m.mu.Unlock()
		cancel()
		return fmt.Errorf("tunnel %s changed while connecting; try again", name)
	case r.sess != nil: // lost a race with another Connect
		m.mu.Unlock()
		cancel()
		return nil
	}
	// The last session's addresses stay the tunnel's servers until this
	// one resolves its own: a block-mode tunnel's reject routes must not
	// hold them meanwhile.
	*r = live{state: domain.TunnelConnecting, detail: "starting", sess: s, want: true, servers: r.servers}
	m.mu.Unlock()
	if d.blocks() {
		m.requestApply() // refuse its networks from now, not from the session's first apply
	}
	m.changed()
	go func() {
		defer close(s.done)
		defer m.finish(name, s)
		drv.run(ctx, m, name, d, p, s)
	}()
	return nil
}

// Disconnect stops a tunnel and waits for it to go down: it's no longer
// wanted, so a block-mode tunnel stops blocking. Disconnecting a tunnel that
// isn't running clears a failed state (and its block).
func (m *Manager) Disconnect(ctx context.Context, name string) error {
	return m.stop(ctx, name, false)
}

// stop is Disconnect; keepWant leaves the tunnel wanted — it's coming back
// (a reconnect with new settings, a restart), so a block-mode one keeps
// blocking meanwhile.
func (m *Manager) stop(ctx context.Context, name string, keepWant bool) error {
	m.mu.Lock()
	r := m.rt[name]
	if r == nil {
		m.mu.Unlock()
		return fmt.Errorf("no tunnel named %q", name)
	}
	wasBlocking := blocking(m.defs[name], r)
	if !keepWant {
		r.want = false
	}
	s := r.sess
	if s == nil {
		r.state, r.lastErr, r.detail = domain.TunnelDisconnected, "", ""
		m.mu.Unlock()
		if wasBlocking && !keepWant {
			_ = m.applyAndWait(ctx, 10*time.Second) // lift its block
		}
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
	case <-time.After(stopGrace):
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
	case <-time.After(killGrace):
		return fmt.Errorf("tunnel %s did not stop", name)
	}
}

// StartAuto connects every tunnel marked auto-connect (daemon startup).
func (m *Manager) StartAuto() {
	if m.isClosed() {
		return
	}
	m.mu.Lock()
	resume := m.resume
	m.resume = nil
	var names []string
	for n, d := range m.defs {
		if d.AutoConnect || resume[n] {
			names = append(names, n)
		}
	}
	m.mu.Unlock()
	slices.Sort(names)
	for _, n := range names {
		if err := m.Connect(n); errors.Is(err, errShuttingDown) {
			return
		} else if err != nil {
			m.o.Log.Warn("tunnel auto-connect failed", "tunnel", n, "err", err)
			m.update(n, func(r *live) { // it may have been deleted meanwhile
				if r.sess == nil {
					r.state, r.lastErr, r.want = domain.TunnelFailed, err.Error(), true
				}
			})
			m.changed()
		}
	}
}

// resumeFile lists the tunnels that were up when the daemon restarted on its
// own (into an update, or back out of one); the next start reconnects them
// along with the auto-connect ones. It is not a definition (.json).
const resumeFile = "resume.list"

// RememberForRestart records the tunnels that are up, so the start after
// this restart brings them back: an automatic update must not quietly drop a
// connection the user made. With keepBlocks, a block-mode tunnel that's
// blocking is brought back too — tried again, rather than unblocked by an
// update — and each of these keeps blocking while the daemon is gone
// (Shutdown). Without it (a rollback: the previous version may not know
// reject routes, and would leave them owned by nothing) every block is
// withdrawn on the way down. Call it before Shutdown.
func (m *Manager) RememberForRestart(keepBlocks bool) {
	m.mu.Lock()
	var names []string
	m.restarting = map[string]bool{}
	for n, r := range m.rt {
		up := r.sess != nil && !r.sess.stopping.Load()
		if up || (keepBlocks && blocking(m.defs[n], r)) {
			names = append(names, n)
			if keepBlocks {
				m.restarting[n] = true
			}
		}
	}
	m.mu.Unlock()
	if len(names) == 0 {
		return
	}
	slices.Sort(names)
	if err := os.WriteFile(filepath.Join(m.o.Dir, resumeFile), []byte(strings.Join(names, "\n")+"\n"), 0o600); err != nil {
		m.o.Log.Warn("can't remember the tunnels to reconnect after the restart", "err", err)
	}
}

// takeResume reads and removes the list RememberForRestart left.
func (m *Manager) takeResume() map[string]bool {
	p := filepath.Join(m.o.Dir, resumeFile)
	b, err := os.ReadFile(p)
	_ = os.Remove(p)
	if err != nil {
		return nil
	}
	out := map[string]bool{}
	for _, n := range strings.Fields(string(b)) {
		if ValidName(n) {
			out[n] = true
		}
	}
	return out
}

// errShuttingDown refuses a connect once Shutdown has begun: an openvpn
// started then would outlive the daemon with nothing to stop it.
var errShuttingDown = errors.New("the daemon is shutting down")

func (m *Manager) isClosed() bool {
	select {
	case <-m.closed:
		return true
	default:
		return false
	}
}

// Resync re-applies the tunnels' routes (retried in the background if the
// apply is refused for now). At startup it withdraws the routes a daemon that
// died with tunnels up left behind — a server pin outlives the tunnel's
// interface.
func (m *Manager) Resync(ctx context.Context) { _ = m.ap.wait(ctx, m.ap.request()) }

// Shutdown stops every tunnel (daemon exit) and withdraws their routes —
// but for the reject routes of the block-mode tunnels the restart will
// bring back (RememberForRestart), which stay while the daemon is gone. The
// withdrawal is waited for only briefly: when something holds the Apply
// Protocol (the updater does, until the process exits) the routes are left
// for the next start to clean up rather than stalling the exit.
func (m *Manager) Shutdown() {
	m.shut.Do(func() {
		close(m.closed)
		m.DisconnectAll()
		_ = m.applyAndWait(context.Background(), shutdownApplyWait)
		m.ap.close()
	})
}

// requestApply asks for the tunnels' routes to be applied, without waiting.
func (m *Manager) requestApply() { m.ap.request() }

// Kick re-applies the tunnels' routes: the daemon calls it when a pending
// route transaction settles, so a tunnel apply it refused goes through at
// once instead of at the next retry.
func (m *Manager) Kick() { m.ap.request() }

// applyAndWait asks for an apply and waits up to d for it to finish.
func (m *Manager) applyAndWait(ctx context.Context, d time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return m.ap.wait(ctx, m.ap.request())
}

// DisconnectAll stops every running tunnel (panic, shutdown); none is
// wanted afterwards, so none blocks — but on the way into a restart, the
// ones it will bring back (RememberForRestart).
func (m *Manager) DisconnectAll() {
	m.mu.Lock()
	keep := map[string]bool{}
	if m.isClosed() {
		keep = m.restarting
	}
	var names []string
	for n, r := range m.rt {
		switch {
		case r.sess != nil:
			names = append(names, n)
		case r.want && !keep[n]:
			r.want = false
			if r.state == domain.TunnelFailed {
				r.state, r.lastErr, r.detail = domain.TunnelDisconnected, "", ""
			}
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
			_ = m.stop(ctx, n, keep[n])
		}()
	}
	wg.Wait()
	m.changed()
}

func (m *Manager) sockPath(name string) string { return filepath.Join(m.runDir, name+".sock") }
func (m *Manager) cfgPath(name string) string  { return filepath.Join(m.runDir, name+".ovpn") }
func (m *Manager) pidPath(name string) string  { return filepath.Join(m.runDir, name+".pid") }

// runOpenVPN is one OpenVPN session, from resolving the server to openvpn's
// exit (ovpnDriver).
func (m *Manager) runOpenVPN(ctx context.Context, name string, d *def, p *Profile, s *session) {
	remotes, bypass, err := m.resolveRemotes(ctx, d.Via, p.Remotes)
	if err != nil {
		m.setErr(name, err.Error())
		return
	}
	servers := bypass
	if d.Via != domain.TunnelViaDirect {
		servers = m.serverAddrs(ctx, p.Remotes)
	}
	m.update(name, func(r *live) { r.bypass, r.servers, r.detail = bypass, servers, "starting openvpn" })
	if len(bypass) > 0 || d.blocks() {
		// Pin the server to the physical gateway before the first packet —
		// and, set to block, refuse its networks, now that a reject route
		// can leave out the network holding the server (one put before its
		// name resolved, at startup, would refuse the connection itself).
		if err := m.applyAndWait(ctx, 10*time.Second); err != nil {
			m.o.Log.Warn("tunnel server not pinned yet; connecting anyway", "tunnel", name, "err", err)
		}
	}

	sock, cfg := m.sockPath(name), m.cfgPath(name)
	_ = os.Remove(sock)
	opts := RenderOptions{Remotes: remotes, Management: sock, IPv6: RoutesNeedIPv6(d.Routes)}
	if err := os.WriteFile(cfg, []byte(p.Render(opts)), 0o600); err != nil {
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
		// The binary goes with the pid, so a later start reaps exactly it.
		pidFile := strconv.Itoa(proc.Pid()) + "\n" + m.o.Launcher.Engine().Path + "\n"
		_ = os.WriteFile(m.pidPath(name), []byte(pidFile), 0o600)
	}
	exited := make(chan struct{})
	go func() { _ = proc.Wait(); close(exited) }()

	dctx, dcancel := context.WithTimeout(ctx, 15*time.Second)
	mc, err := dialMgmt(dctx, sock, exited)
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
	// openvpn waits in its management hold until released; the HOLD
	// notification it sends on our connecting does that (see handle).
	for _, c := range []string{"state on", "bytecount 5"} {
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
			iface, nets := m.findIface(ctx, st.localIP, st.localIPv6)
			if iface == "" {
				// What it routes can't be checked (or routed) without it.
				stop("connected, but no interface holds the tunnel's address " + strings.Trim(st.localIP+" "+st.localIPv6, " ") + "; refusing")
				return
			}
			if why := m.vetAddressing(ctx, name, iface, nets); why != "" {
				stop(why)
				return
			}
			now := time.Now()
			m.update(name, func(r *live) {
				r.state, r.detail, r.lastErr, r.failures = domain.TunnelConnected, "", "", 0
				if st.desc == "ERROR" {
					r.detail = "connected with errors"
				}
				r.iface, r.localIP, r.v6 = iface, st.localIP, st.localIPv6 != ""
				r.server = st.remoteIP
				if st.remotePort != "" {
					r.server += ":" + st.remotePort
				}
				// The address openvpn actually connected to is one of its
				// servers, whatever DNS said when the session started.
				if a, err := netip.ParseAddr(st.remoteIP); err == nil && !slices.Contains(r.servers, a.Unmap()) {
					r.servers = append(r.servers, a.Unmap())
				}
				r.since = &now
			})
			m.requestApply()
		case "RECONNECTING":
			var tail []string
			if p, ok := s.proc.Load().(Process); ok {
				tail = p.Tail()
			}
			var giveUp, reresolve, wasUp bool
			m.update(name, func(r *live) {
				wasUp = r.state == domain.TunnelConnected
				r.state, r.detail = domain.TunnelReconnecting, st.desc
				r.failures++
				if r.since == nil { // never got through: explain why, if openvpn's output says
					if why := diagnose(name, st.desc, tail); why != "" {
						r.lastErr = why
					}
					giveUp = r.failures >= maxFailedAttempts
				} else {
					reresolve = r.failures%reresolveAfter == 0
				}
			})
			if wasUp {
				m.requestApply() // its destinations leave it (or are refused) until it's back
			}
			if giveUp {
				m.update(name, func(r *live) {
					if r.lastErr == "" {
						r.lastErr = fmt.Sprintf("couldn't connect after %d attempts (%s)", r.failures, st.desc)
					} else {
						r.lastErr = fmt.Sprintf("gave up after %d attempts: %s", r.failures, r.lastErr)
					}
				})
				_ = mc.send("signal SIGTERM")
			} else if reresolve && d.Via == domain.TunnelViaDirect {
				go m.reresolve(ctx, name, d, s)
			}
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
		// management-hold pauses openvpn at start, so nothing happens before
		// the daemon is listening: that one is released at once. The hold
		// stays on, so every restart (a dropped attempt, ping-restart) waits
		// in it too; releasing only after the backoff openvpn reports (at
		// least holdBackoffMin) keeps a failing login from being retried back
		// to back. And if the daemon goes away, management-signal restarts
		// openvpn into that hold, where it waits for good — it never runs
		// unsupervised.
		if s.released.CompareAndSwap(false, true) {
			_ = mc.send("hold release")
			return
		}
		wait := min(max(parseHold(ev.body), holdBackoffMin), holdBackoffMax)
		go func() {
			select {
			case <-ctx.Done():
			case <-time.After(wait):
				_ = mc.send("hold release")
			}
		}()
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

// reresolve looks a connected-before tunnel's server names up again after
// repeated failed reconnects, and restarts the session when their addresses
// moved: openvpn only knows (and the pins only cover) the old ones.
func (m *Manager) reresolve(ctx context.Context, name string, d *def, s *session) {
	now := time.Now().Unix()
	if last := s.resolved.Load(); now-last < 60 || !s.resolved.CompareAndSwap(last, now) {
		return // at most once a minute
	}
	m.mu.Lock()
	p, r := m.parsed[name], m.rt[name]
	if p == nil || r == nil || r.sess != s {
		m.mu.Unlock()
		return
	}
	old := append([]netip.Addr(nil), r.bypass...)
	m.mu.Unlock()
	if !hasHostname(p.remotes) {
		return
	}
	_, pins, err := m.resolveRemotes(ctx, d.Via, p.remotes)
	if err != nil || sameAddrs(old, pins) {
		return
	}
	m.o.Log.Info("tunnel server addresses changed; reconnecting", "tunnel", name)
	m.mu.Lock()
	current := m.rt[name] != nil && m.rt[name].sess == s
	m.mu.Unlock()
	if !current || s.stopping.Load() {
		return
	}
	dctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := m.Disconnect(dctx, name); err == nil {
		_ = m.Connect(name)
	}
}

func hasHostname(rs []Remote) bool {
	for _, r := range rs {
		if !IsAddr(r.Host) {
			return true
		}
	}
	return false
}

func sameAddrs(a, b []netip.Addr) bool {
	return slices.Equal(slices.SortedFunc(slices.Values(a), netip.Addr.Compare), slices.SortedFunc(slices.Values(b), netip.Addr.Compare))
}

// vetAddressing checks the addressing the server gave the tunnel (see
// addressing.go) against this machine: its interfaces, the kernel's routes
// into the tunnel, the protected addresses and the tunnel's own servers.
func (m *Manager) vetAddressing(ctx context.Context, name, iface string, nets []netip.Prefix) string {
	return m.vet(ctx, name, iface, nets, false)
}

// vetConfigured is vetAddressing for addresses from the tunnel's own
// configuration (WireGuard's), checked before the interface holds them.
func (m *Manager) vetConfigured(ctx context.Context, name, iface string, nets []netip.Prefix) string {
	return m.vet(ctx, name, iface, nets, true)
}

func (m *Manager) vet(ctx context.Context, name, iface string, nets []netip.Prefix, configured bool) string {
	env := addressingEnv{iface: iface, configured: configured}
	if m.o.Ifaces != nil {
		env.ifaces, _ = m.o.Ifaces(ctx)
	}
	if m.o.Protected != nil {
		env.protected = m.o.Protected(ctx)
	}
	m.mu.Lock()
	// Every running tunnel's servers: a peer at another's would carry that
	// tunnel's connection through this one.
	for n, r := range m.rt {
		if n == name || r.sess != nil {
			env.servers = append(append(env.servers, r.servers...), r.bypass...)
		}
	}
	// Its own routes: on a reconnect they're still on the (persisted)
	// interface, and macOS doesn't tag them as RiftRoute's.
	var listed []netip.Prefix
	if d := m.defs[name]; d != nil {
		for _, s := range d.Routes {
			if p, ok := routePrefix(s); ok {
				listed = append(listed, p)
			}
		}
	}
	m.mu.Unlock()
	// …and every route RiftRoute installed into it: a tunnel-mode profile's
	// too (Owned).
	if m.o.Owned != nil {
		for _, o := range m.o.Owned() {
			if o.ProfileID == routing.TunnelProfilePrefix+name && o.Route.Gateway == "" {
				if p, ok := routePrefix(o.Route.DstCIDR); ok {
					listed = append(listed, p)
				}
			}
		}
	}
	env.ours = routing.Aggregate(listed)
	var routes []domain.Route
	if m.o.Routes != nil {
		routes, _ = m.o.Routes(ctx)
	}
	return vetAddressing(nets, routes, env)
}

// finish records the end of a session and withdraws its routes.
func (m *Manager) finish(name string, s *session) {
	m.mu.Lock()
	if r := m.rt[name]; r != nil && r.sess == s {
		r.sess, r.iface, r.bypass, r.detail = nil, "", nil, ""
		if !r.want {
			r.servers = nil // kept while it's wanted: see Inputs
		}
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
	// Withdraw its routes. A shutdown doesn't wait per tunnel (Shutdown
	// withdraws once, after all of them); otherwise Disconnect returns once
	// the routes are gone, or soon after if the protocol is busy.
	if m.isClosed() {
		m.requestApply()
	} else {
		_ = m.applyAndWait(context.Background(), 10*time.Second)
	}
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
			if !pinnable(a) {
				// A pin routes the address around every other VPN: never for
				// loopback, link-local, multicast or "any" — whatever a
				// profile or its DNS says.
				m.o.Log.Warn("tunnel server address not usable; skipped", "host", r.Host, "addr", a)
				continue
			}
			if !seen[a] && len(pins) == maxPins {
				continue // enough: openvpn gets at most maxPins servers
			}
			out = append(out, Remote{Host: a.String(), Port: r.Port, Proto: r.Proto})
			if !seen[a] {
				seen[a] = true
				pins = append(pins, a)
			}
		}
	}
	if len(out) == 0 {
		return nil, nil, errors.New("couldn't resolve any of the profile's servers to a usable address")
	}
	// IPv4 first: openvpn tries remotes in order, and a v4 pin is the one a
	// v4-only network can honor.
	slices.SortStableFunc(out, func(a, b Remote) int {
		return cmpBool(IsAddr(a.Host) && netip.MustParseAddr(a.Host).Is4(), IsAddr(b.Host) && netip.MustParseAddr(b.Host).Is4())
	})
	return out, pins, nil
}

// serverAddrs resolves the profile's servers the way openvpn will (best
// effort: a name that doesn't resolve here is openvpn's to retry), for a
// tunnel that isn't pinned.
func (m *Manager) serverAddrs(ctx context.Context, rs []Remote) []netip.Addr {
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	add := func(a netip.Addr) {
		if a = a.Unmap(); a.IsValid() && !seen[a] && len(out) < maxPins {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, r := range rs {
		if a, err := netip.ParseAddr(r.Host); err == nil {
			add(a)
			continue
		}
		if m.o.Resolve == nil {
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		addrs, _ := m.o.Resolve(rctx, r.Host)
		cancel()
		for _, a := range addrs {
			add(a)
		}
	}
	return out
}

// maxPins caps the server addresses one tunnel pins to the physical gateway
// (each is a route around the other VPNs).
const maxPins = 16

// pinnable reports whether a server address may be pinned to the physical
// gateway.
func pinnable(a netip.Addr) bool {
	return a.IsValid() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() &&
		!a.IsLinkLocalUnicast() && !a.IsLinkLocalMulticast() && !a.IsInterfaceLocalMulticast() &&
		a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// findIface finds the interface holding the tunnel's IPv4 or IPv6 address
// (openvpn doesn't report its device name), waiting briefly for it to
// appear, and returns the networks assigned to it.
func (m *Manager) findIface(ctx context.Context, ips ...string) (string, []netip.Prefix) {
	var want []netip.Addr
	for _, ip := range ips {
		if a, err := netip.ParseAddr(ip); err == nil {
			want = append(want, a)
		}
	}
	if len(want) == 0 || m.o.Ifaces == nil {
		return "", nil
	}
	for range 30 {
		ifs, _ := m.o.Ifaces(ctx)
		for _, ifc := range ifs {
			if !slices.ContainsFunc(want, func(a netip.Addr) bool { return holds(ifc.Addrs, a) }) {
				continue
			}
			var nets []netip.Prefix
			for _, a := range ifc.Addrs {
				if p, err := netip.ParsePrefix(a); err == nil {
					nets = append(nets, p)
				}
			}
			return ifc.Name, nets
		}
		select {
		case <-ctx.Done():
			return "", nil
		case <-time.After(100 * time.Millisecond):
		}
	}
	return "", nil
}

func holds(addrs []string, want netip.Addr) bool {
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a); err == nil && p.Addr() == want {
			return true
		}
		if x, err := netip.ParseAddr(a); err == nil && x == want {
			return true
		}
	}
	return false
}

func (m *Manager) update(name string, fn func(*live)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.rt[name]; r != nil {
		fn(r)
	}
}

// rememberLogin records that tunnel name's login print connected.
func (m *Manager) rememberLogin(name, print string) {
	m.loginMu.Lock()
	defer m.loginMu.Unlock()
	if m.logins == nil {
		m.logins = map[string]string{}
	}
	if m.logins[name] == print {
		return
	}
	m.logins[name] = print
	if err := m.store.putLogin(name, print); err != nil {
		m.o.Log.Debug("tunnel login not recorded", "tunnel", name, "err", err)
	}
}

// loggedIn is the print of tunnel name's login that last connected (since
// it was saved, across restarts), or "".
func (m *Manager) loggedIn(name string) string {
	m.loginMu.Lock()
	defer m.loginMu.Unlock()
	if p, ok := m.logins[name]; ok {
		return p
	}
	if m.logins == nil {
		m.logins = map[string]string{}
	}
	m.logins[name] = m.store.getLogin(name)
	return m.logins[name]
}

// forgetLogin drops tunnel name's record — it's deleted, or its login was
// rejected over and over (the next rejection then stops it at once).
func (m *Manager) forgetLogin(name string) {
	m.loginMu.Lock()
	defer m.loginMu.Unlock()
	if m.logins == nil {
		m.logins = map[string]string{}
	}
	m.logins[name] = ""
	m.store.removeLogin(name)
}

func (m *Manager) setErr(name, msg string) {
	m.o.Log.Warn("tunnel error", "tunnel", name, "err", msg)
	m.update(name, func(r *live) { r.lastErr = msg })
	m.changed()
}

func (m *Manager) changed() {
	m.observe()
	if m.o.OnChange != nil {
		m.o.OnChange()
	}
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
			first, bin, _ := strings.Cut(strings.TrimSpace(string(data)), "\n")
			ours := func(pid int) bool { return ourCommandLine(processArgs(pid), strings.TrimSpace(bin), m.runDir) }
			if pid, err := strconv.Atoi(strings.TrimSpace(first)); err == nil && pid > 1 && ours(pid) {
				m.o.Log.Info("stopping openvpn left by a previous daemon", "pid", pid)
				if !stopProcess(pid, ours) {
					// Keep its pid file: the next start tries again rather
					// than running a second session beside it.
					m.o.Log.Error("openvpn left by a previous daemon won't stop", "pid", pid)
					continue
				}
			}
			_ = os.Remove(filepath.Join(m.runDir, n))
		case strings.HasSuffix(n, ".sock"), strings.HasSuffix(n, ".ovpn"), strings.HasPrefix(n, ".tmp-"),
			// an IKEv2 session's (ikeconf.go): its config, keys and socket
			strings.HasSuffix(n, ".conf"), strings.HasSuffix(n, ".pem"), strings.HasSuffix(n, ".p12"), strings.HasSuffix(n, ".vici"):
			_ = os.Remove(filepath.Join(m.runDir, n))
		}
	}
}

// stopProcess sends pid SIGTERM, then SIGKILL if it's still there after 3
// seconds, re-checking before each signal that it's still the process ours
// says it is (pids get reused). It reports whether the process is gone.
func stopProcess(pid int, ours func(int) bool) bool {
	for _, kill := range []func(int) error{terminate, forceKill} {
		if !alive(pid) || !ours(pid) {
			return true
		}
		_ = kill(pid)
		for i := 0; i < 30 && alive(pid); i++ {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return !alive(pid)
}

// Engine reports whether tunnels can run on this machine, and if not, how
// to install what's missing: openvpn's, with IKEv2's (strongSwan) beside it.
// WireGuard is built in.
func (m *Manager) Engine() domain.TunnelEngine {
	e := m.o.Launcher.Engine()
	ike := m.drivers[domain.TunnelIKEv2].engine()
	e.IKEv2 = &ike
	return e
}

// ourCommandLine reports whether a process's command line is an openvpn or
// charon-cmd we started: the binary recorded with its pid (any openvpn by
// name for a pid file without one, from before charon-cmd), running a config
// (openvpn) or key (charon-cmd) from our run directory — so a recycled pid,
// or one the user started themselves, is never killed.
func ourCommandLine(args, bin, runDir string) bool {
	argv0, rest, _ := strings.Cut(args, " ")
	if bin != "" {
		if argv0 != bin {
			return false
		}
	} else if b := filepath.Base(argv0); b != "openvpn" && b != "riftroute-openvpn" {
		return false
	}
	dir := runDir + string(filepath.Separator)
	return strings.Contains(" "+rest, " --config "+dir) || strings.Contains(" "+rest, " --priv "+dir) ||
		strings.Contains(" "+rest, " --p12 "+dir)
}

// processArgs returns a process's command line, or "" if it's gone. Linux
// reads /proc (BusyBox's ps, on Alpine and the like, has no -p).
func processArgs(pid int) string {
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
		if err != nil {
			return ""
		}
		return strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// A fixed path: a root daemon never takes ps from its environment.
	out, err := exec.CommandContext(ctx, "/bin/ps", "-o", "args=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
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
