package tunnel

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// ikev2Driver runs IKEv2 connections from configuration profiles
// (.mobileconfig) on strongSwan's charon-cmd (docs/tunnels-ikev2.md).
type ikev2Driver struct{ o *Options }

func (ikev2Driver) parse(config string) (*parsed, error) {
	c, err := ParseMobileconfig(config)
	if err != nil {
		return nil, err
	}
	return &parsed{
		remotes: []Remote{c.Remote}, servers: c.Servers(), ignored: c.Ignored, ike: c,
		// An EAP login's username and password: the profile's, or the
		// user's (a profile may leave the password for the device to ask).
		needsAuth: c.Auth == IKEv2EAP, inlineUser: c.Username, inlinePass: c.Password,
	}, nil
}

func (i ikev2Driver) engine() domain.TunnelEngine {
	if i.o.IKE == nil {
		return domain.TunnelEngine{Problem: "IKEv2 tunnels aren't set up in this daemon"}
	}
	return i.o.IKE.Engine()
}

// check refuses a login this system's charon-cmd can't do: a shared secret
// needs strongSwan 6.1 (RiftRoute's own on macOS has it; a Linux
// distribution's may be older).
func (i ikev2Driver) check(p *parsed) error {
	switch p.ike.Auth {
	case IKEv2Certificate, IKEv2EAP:
		return nil
	case IKEv2PSK:
		if i.o.IKE == nil {
			return nil // the engine check says why
		}
		if v := i.o.IKE.Engine().Version; !ikePSKSupported(v) {
			return fmt.Errorf("this profile logs in with a shared secret, which needs strongSwan %s or later; "+
				"this system's charon-cmd is %s", ikePSKSince, v)
		}
		return nil
	}
	return errors.New(ikeLoginUnsupported(p.ike.Auth))
}

func (i ikev2Driver) run(ctx context.Context, m *Manager, name string, d *def, p *parsed, s *session) {
	(&ikeSession{m: m, name: name, d: d, c: p.ike, s: s, l: i.o.IKE}).run(ctx)
}

// The IKEv2 session's timing (vars for tests).
var (
	// ikePoll is how often charon is asked for the connection's state.
	ikePoll = time.Second
	// ikeStartWait: a charon-cmd whose VICI socket isn't up by then didn't
	// start.
	ikeStartWait = 15 * time.Second
	// ikeConnectWait: an attempt not connected by then is given up (charon
	// retransmits for about 165 s before it gives up on its own).
	ikeConnectWait = 3 * time.Minute
	// ikeDownAfter: a connection that has been down this long has dropped
	// (a rekey can show none established for a moment).
	ikeDownAfter = 5 * time.Second
	// ikeStopWait is how long a stopped charon-cmd gets to delete the
	// connection with the server and exit, before it's killed.
	ikeStopWait = 4 * time.Second
	// ikeBackoff bounds the pause before the next attempt.
	ikeBackoffMin, ikeBackoffMax = 2 * time.Second, time.Minute
	// ikeRejectWaits are the pauses before trying again a login the server
	// rejected after it had worked (its backend's trouble, likely): a few
	// tries over an hour, so a password that really changed can't lock the
	// account. One more rejection in a row and the session ends.
	ikeRejectWaits = []time.Duration{5 * time.Minute, 15 * time.Minute, 30 * time.Minute}
)

// ikeSession is one IKEv2 session: a charon-cmd per attempt, restarted
// until the tunnel is stopped (charon-cmd exits when an attempt fails, but
// not when an established connection drops).
type ikeSession struct {
	m    *Manager
	name string
	d    *def
	c    *IKEv2Config
	s    *session
	l    IKELauncher

	remotes  []Remote // what charon-cmd connects to: the pinned addresses (via direct), or the name
	resolved time.Time
}

// errFatal ends the session: retrying can't help (the profile, the engine,
// the tunnel's addressing).
type errFatal struct{ msg string }

func (e errFatal) Error() string { return e.msg }

// errRejected: the server rejected a login that had worked; tried again,
// slowly (ikeRejectWaits).
type errRejected struct{ msg string }

func (e errRejected) Error() string { return e.msg }

func (k *ikeSession) run(ctx context.Context) {
	if err := k.resolve(ctx); err != nil {
		k.m.setErr(k.name, err.Error())
		return
	}
	rejects := 0 // rejections in a row of a login that had worked
	for attempt := 0; ; attempt++ {
		wasUp, err := k.attempt(ctx, k.remotes[attempt%len(k.remotes)].Host)
		if ctx.Err() != nil || k.s.stopping.Load() {
			return
		}
		var fatal errFatal
		if errors.As(err, &fatal) {
			k.m.setErr(k.name, fatal.msg)
			return
		}
		var rejected errRejected
		switch {
		case errors.As(err, &rejected):
			rejects++
			if rejects > len(ikeRejectWaits) {
				k.m.setErr(k.name, fmt.Sprintf("gave up after %d rejections in a row: %s", rejects, rejected.msg))
				return
			}
		case wasUp:
			rejects = 0
		}
		giveUp := false
		var failures int
		k.m.update(k.name, func(r *live) {
			r.state, r.iface, r.detail = domain.TunnelReconnecting, "", "waiting to reconnect"
			r.failures++
			failures = r.failures
			if err != nil {
				r.lastErr = err.Error()
			}
			giveUp = r.since == nil && r.failures >= maxFailedAttempts
		})
		if wasUp {
			k.m.requestApply() // its destinations leave it (or are refused) until it's back
		}
		if giveUp {
			k.m.update(k.name, func(r *live) {
				r.lastErr = fmt.Sprintf("gave up after %d attempts: %s", r.failures, lastLine([]string{r.lastErr}, "no connection"))
			})
			k.m.changed()
			return
		}
		k.m.changed()
		wait := min(ikeBackoffMin<<min(failures-1, 10), ikeBackoffMax)
		if rejects > 0 && errors.As(err, &rejected) {
			wait = ikeRejectWaits[rejects-1]
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if time.Since(k.resolved) >= time.Minute && hasHostname([]Remote{k.c.Remote}) {
			_ = k.resolve(ctx) // the server's addresses may have moved; keep the old ones if it fails
		}
	}
}

// resolve picks the addresses charon-cmd connects to and pins them (via
// direct), applying the change before the next packet.
func (k *ikeSession) resolve(ctx context.Context) error {
	k.resolved = time.Now()
	remotes, pins, err := k.m.resolveRemotes(ctx, k.d.Via, []Remote{k.c.Remote})
	if err != nil {
		return err
	}
	servers := pins
	if k.d.Via != domain.TunnelViaDirect {
		servers = k.m.serverAddrs(ctx, []Remote{k.c.Remote})
	}
	first := k.remotes == nil
	if !first && sameAddrs(pinsOf(k.m, k.name), pins) {
		return nil
	}
	k.remotes = remotes
	k.m.update(k.name, func(r *live) { r.bypass, r.servers = pins, servers })
	if (len(pins) > 0 || (first && k.d.blocks())) && ctx.Err() == nil {
		// Pin the server to the physical gateway before the first packet
		// (and, set to block, refuse its networks: see runOpenVPN).
		if err := k.m.applyAndWait(ctx, 10*time.Second); err != nil {
			k.m.o.Log.Warn("tunnel server not pinned yet; connecting anyway", "tunnel", k.name, "err", err)
		}
	}
	return nil
}

// attempt runs one charon-cmd, connecting to host, until it exits, the
// connection it made drops, or the session is stopped. wasUp: it connected.
func (k *ikeSession) attempt(ctx context.Context, host string) (wasUp bool, err error) {
	m := k.m
	login := ikeLogin{User: orString(k.d.Username, k.c.Username), Password: orString(k.d.Password, k.c.Password)}
	setup, err := renderIKE(k.c, login, ikeRoots(k.c), host, m.runDir, k.name, RoutesNeedIPv6(k.d.Routes), ikeKeyAsP12(k.l.Engine().Version))
	if err != nil {
		return false, errFatal{err.Error()}
	}
	defer removeIKEFiles(setup)
	removeIKEFiles(setup) // a crashed run's
	for _, f := range setup.Files {
		if err := os.WriteFile(f.Name, f.Data, 0o600); err != nil {
			return false, errFatal{"write the connection's files: " + err.Error()}
		}
	}
	m.update(k.name, func(r *live) {
		if r.state != domain.TunnelReconnecting {
			r.state = domain.TunnelConnecting
		}
		r.detail = "starting strongSwan"
	})
	m.changed()
	proc, err := k.l.Start(IKESpec{Name: k.name, Args: setup.Args, Conf: setup.Conf, Socket: setup.Socket, Stdin: setup.Stdin, Config: k.c})
	if err != nil {
		return false, errFatal{err.Error()}
	}
	k.s.proc.Store(Process(proc))
	if proc.Pid() != os.Getpid() {
		// The binary goes with the pid, so a later start reaps exactly it.
		_ = os.WriteFile(m.pidPath(k.name), []byte(strconv.Itoa(proc.Pid())+"\n"+k.l.Engine().Path+"\n"), 0o600)
		defer os.Remove(m.pidPath(k.name))
	}
	exited := make(chan struct{})
	go func() { _ = proc.Wait(); close(exited) }()
	stop := func() {
		_ = proc.Stop()
		select {
		case <-exited:
		case <-time.After(ikeStopWait):
			_ = proc.Kill()
			<-exited
		}
	}

	start := time.Now()
	var seen bool           // charon answered on its socket
	var downSince time.Time // when an up connection was last seen down
	var vips []netip.Addr   // the addresses the connection is routed with
	tick := time.NewTicker(ikePoll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			stop()
			return wasUp, nil
		case <-exited:
			if wasUp {
				return true, errors.New("strongSwan exited: " + lastLine(proc.Tail(), "no output"))
			}
			why := diagnoseIKE(k.name, k.d.Via, k.c.Auth, proc.Tail())
			if k.c.Auth == IKEv2EAP && ikeRejected(proc.Tail()) {
				if k.loginWorked() {
					// It connected with this very login: likely the server's
					// backend (RADIUS, the directory) failing for a moment.
					return false, errRejected{why}
				}
				// Never worked: trying the same password again could lock
				// the account.
				return false, errFatal{why}
			}
			return false, errors.New(why)
		case <-tick.C:
		}
		qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		st, err := proc.Status(qctx)
		cancel()
		now := time.Now()
		var lost error // charon answered before, and doesn't now
		switch {
		case err != nil && !seen:
			if now.Sub(start) > ikeStartWait {
				stop()
				return false, errors.New("strongSwan didn't start: " + lastLine(proc.Tail(), err.Error()))
			}
			continue
		case err != nil:
			// A charon that stops answering can't say the connection is
			// still there: it counts as down, so a wedged one doesn't keep a
			// dead tunnel "connected" (its routes, no block).
			lost, st = err, IKEStatus{}
		default:
			seen = true
			m.update(k.name, func(r *live) { r.in, r.out = st.In, st.Out })
		}
		switch {
		case st.Up && !wasUp:
			if why := k.connected(ctx, st); why != "" {
				stop()
				return false, errFatal{why}
			}
			wasUp, downSince, vips = true, time.Time{}, st.VIPs
		case st.Up:
			downSince = time.Time{}
			if len(st.VIPs) > 0 && !sameAddrs(st.VIPs, vips) {
				// charon made the connection again (the network changed;
				// dead-peer detection) and the server handed out another
				// address: follow it, once an interface holds it.
				done, why := k.readdress(ctx, st)
				if why != "" {
					stop()
					return true, errFatal{why}
				}
				if done {
					vips = st.VIPs
				}
			}
		case wasUp && downSince.IsZero():
			downSince = now
		case wasUp && now.Sub(downSince) >= ikeDownAfter:
			// charon-cmd stays up with no connection: restart it.
			stop()
			if lost != nil {
				return true, errors.New("strongSwan stopped answering (" + lost.Error() + ")")
			}
			return true, errors.New("the connection to the server dropped")
		case !wasUp && now.Sub(start) > ikeConnectWait:
			stop()
			return false, errors.New(diagnoseIKE(k.name, k.d.Via, k.c.Auth, proc.Tail()))
		case !wasUp:
			detail := "connecting"
			if st.State != "" {
				detail = strings.ToLower(st.State)
			}
			m.update(k.name, func(r *live) { r.detail = detail })
			m.changed()
		}
	}
}

// ikeAddressing is where a connection's addresses are.
type ikeAddressing struct {
	iface, local string // the interface holding them; the IPv4 one
	v6           bool
	ips          []string
}

// address finds the interface holding the connection's addresses (none:
// a.iface is empty) and vets them; why says why they're refused.
func (k *ikeSession) address(ctx context.Context, st IKEStatus) (a ikeAddressing, why string) {
	for _, ip := range st.VIPs {
		a.ips = append(a.ips, ip.String())
		if ip.Is4() && a.local == "" {
			a.local = ip.String()
		}
		a.v6 = a.v6 || ip.Is6()
	}
	iface, nets := k.m.findIface(ctx, a.ips...)
	if iface == "" {
		return a, ""
	}
	a.iface = iface
	return a, k.m.vetAddressing(ctx, k.name, iface, nets)
}

// readdress follows a connection made again with other addresses: done
// once an interface holds them (until then, the next poll looks again);
// why says why they're refused.
func (k *ikeSession) readdress(ctx context.Context, st IKEStatus) (done bool, why string) {
	a, why := k.address(ctx, st)
	if a.iface == "" || why != "" {
		return false, why
	}
	k.m.o.Log.Info("tunnel's address changed", "tunnel", k.name, "iface", a.iface, "addrs", strings.Join(a.ips, " "))
	k.m.update(k.name, func(r *live) { r.iface, r.localIP, r.v6 = a.iface, a.local, a.v6 })
	k.m.requestApply() // its routes, into the interface that holds it now
	k.m.changed()
	return true, ""
}

// connected records the connection and has its routes applied, or says
// why it's refused: without an address from the server, the tunnel's
// traffic can't be told apart; an address that clashes with this machine's
// networks would cut it off.
func (k *ikeSession) connected(ctx context.Context, st IKEStatus) string {
	if len(st.VIPs) == 0 {
		return "connected, but the server assigned no address (virtual IP) to this client; RiftRoute routes " +
			"only into a tunnel that has one — the server must hand out addresses (e.g. strongSwan's rightsourceip)"
	}
	a, why := k.address(ctx, st)
	if a.iface == "" {
		return "connected, but no interface holds the tunnel's address " + strings.Join(a.ips, " ") + "; refusing"
	}
	if why != "" {
		return why
	}
	now := time.Now()
	login := k.loginPrint()
	k.m.update(k.name, func(r *live) {
		r.loggedIn = login
		r.state, r.detail, r.lastErr, r.failures = domain.TunnelConnected, "", "", 0
		r.iface, r.localIP, r.v6 = a.iface, a.local, a.v6
		if st.Server.IsValid() {
			r.server = st.Server.String()
			// The address charon actually reached is one of its servers.
			if !slices.Contains(r.servers, st.Server.Addr()) {
				r.servers = append(r.servers, st.Server.Addr())
			}
		}
		r.since = &now
	})
	k.m.requestApply()
	k.m.changed()
	return ""
}

// loginPrint fingerprints the session's login: the profile and what it
// logs in with.
func (k *ikeSession) loginPrint() string {
	h := sha256.Sum256([]byte(k.d.Config + "\x00" + k.d.Username + "\x00" + k.d.Password))
	return hex.EncodeToString(h[:])
}

// loginWorked reports whether this very login has connected (since the
// daemon started).
func (k *ikeSession) loginWorked() bool {
	login, worked := k.loginPrint(), false
	k.m.update(k.name, func(r *live) { worked = r.loggedIn == login })
	return worked
}

// ikeRejected reports whether the server turned the login down: it said
// so, or MSCHAPv2 failed with the password (not for want of the plugin).
func ikeRejected(tail []string) bool {
	for _, l := range tail {
		for _, sub := range []string{"AUTHENTICATION_FAILED", "EAP_FAILURE", "EAP-MS-CHAPv2 failed with error"} {
			if strings.Contains(l, sub) {
				return true
			}
		}
	}
	return false
}

// diagnoseIKE turns charon-cmd's output from a failed attempt into the likely
// cause and its fix.
func diagnoseIKE(name string, via domain.TunnelVia, auth IKEv2Auth, tail []string) string {
	has := func(sub string) (string, bool) {
		for i := len(tail) - 1; i >= 0; i-- {
			if strings.Contains(tail[i], sub) {
				return strings.TrimSpace(tail[i]), true
			}
		}
		return "", false
	}
	for _, l := range tail {
		// "plugin 'x': failed to load - …" or "plugin 'x' failed to load:
		// …" — not a feature "in plugin 'x'" that failed.
		if m := rePluginMissing.FindStringSubmatch(l); m != nil &&
			(slices.Contains(ikeEssential, m[1]) || auth == IKEv2EAP && slices.Contains(ikeEAPPlugins, m[1])) {
			return missingPlugin(m[1])
		}
		if auth == IKEv2EAP && strings.Contains(l, "loading EAP_MSCHAPV2 method failed") {
			return missingPlugin("eap-mschapv2")
		}
	}
	if l, ok := has("critical plugin"); ok {
		msg := "strongSwan couldn't load a part IKEv2 tunnels need (" + l + ")"
		if runtime.GOOS == "linux" {
			msg += " — " + ikeLinuxNote
		}
		return msg
	}
	if ikeRejected(tail) {
		switch auth {
		case IKEv2EAP:
			return "the server rejected the username or password — change them with `riftroute tunnel edit " + name +
				" --username <name> --ask-password` (or on the Tunnels page), then connect again"
		case IKEv2PSK:
			return "the server rejected the shared secret, or this client's identity (the profile's LocalIdentifier)"
		}
	}
	for _, c := range []struct{ sub, msg string }{
		{"AUTHENTICATION_FAILED", "the server rejected this profile's certificate (AUTHENTICATION_FAILED) — it may have been revoked, or the server expects another login"},
		{"NO_PROPOSAL_CHOSEN", "the server accepts none of the profile's encryption settings (NO_PROPOSAL_CHOSEN)"},
		{"TS_UNACCEPTABLE", "the server refused the traffic it was asked to carry (TS_UNACCEPTABLE)"},
		{"does not match to", "the server identified itself differently than the profile's RemoteIdentifier expects"},
		{"constraint check failed", "the server's certificate doesn't carry the name the profile's RemoteIdentifier expects"},
		{"no trusted", "the server's certificate isn't one the profile's certificate authorities vouch for (or doesn't carry the name in its RemoteIdentifier)"},
		{"certificate status is not available", "the server's certificate couldn't be verified"},
		{"has expired", "a certificate has expired (the profile's, or the server's)"},
		{"loading certificate from", "strongSwan couldn't read the profile's certificates"},
		{"loading PKCS#12 file", "strongSwan couldn't read the profile's certificate and key"},
		{"private key from", "strongSwan couldn't read the profile's private key"},
	} {
		if _, ok := has(c.sub); ok {
			return c.msg
		}
	}
	if _, ok := has("retransmit"); ok {
		msg := "the server didn't answer: it can't be reached, or UDP ports 500 and 4500 to it are blocked"
		if via == domain.TunnelViaDirect {
			msg += " — another VPN's firewall (e.g. Windscribe's) may be blocking traffic outside its tunnel; allow the " +
				"server there, or reach it through the main VPN (--via default)"
		}
		return msg
	}
	return "couldn't connect: " + lastLine(tail, "strongSwan gave no reason") + " — see `riftroute tunnel log " + name + "`"
}

var rePluginMissing = regexp.MustCompile(`(?:^|\] )plugin '([a-z0-9-]+)':? failed to load`)

// missingPlugin explains a session that couldn't load one of strongSwan's
// essential plugins.
func missingPlugin(p string) string {
	msg := "strongSwan's " + p + " plugin isn't installed, and IKEv2 tunnels need it"
	if runtime.GOOS == "linux" {
		msg += " — " + ikeLinuxNote
	}
	return msg
}

// ikeRootBundles are where each system keeps the CAs it trusts, one PEM
// bundle: a profile that carries no CA of its own trusts those (as it would
// on the device it was made for).
var ikeRootBundles = map[string][]string{
	"darwin": {"/etc/ssl/cert.pem"},
	"linux":  {"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem", "/etc/ssl/cert.pem"},
}

// ikeRoots are the system's CAs for a profile without its own (nil
// otherwise, or if none can be read).
func ikeRoots(c *IKEv2Config) []*x509.Certificate {
	if len(c.CAs) > 0 || len(c.Chain) > 0 {
		return nil
	}
	for _, p := range ikeRootBundles[runtime.GOOS] {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var out []*x509.Certificate
		for {
			var b *pem.Block
			if b, data = pem.Decode(data); b == nil {
				break
			}
			if b.Type != "CERTIFICATE" {
				continue
			}
			if cert, err := x509.ParseCertificate(b.Bytes); err == nil && cert.IsCA {
				out = append(out, cert)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

// removeIKEFiles removes a session's files and charon's socket.
func removeIKEFiles(st ikeSetup) {
	for _, f := range st.Files {
		_ = os.Remove(f.Name)
	}
	_ = os.Remove(st.Socket)
}
