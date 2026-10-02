package tunnel

import (
	"strings"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/telemetry"
)

// The anonymous report's tunnel counts (docs/telemetry.md): sessions that
// connected, dropped, gave up, and failed attempts by cause. They're read
// off each tunnel's state as it changes, the same way for every protocol.

// seen is what observe saw of a tunnel last.
type seen struct {
	state    domain.TunnelState
	failures int
}

// observe counts what changed since it last looked (Options.Count; under
// changed()).
func (m *Manager) observe() {
	if m.o.Count == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil {
		m.seen = map[string]seen{}
	}
	for name, r := range m.rt {
		typ := string(domain.TunnelOpenVPN)
		if d := m.defs[name]; d != nil && d.Type != "" {
			typ = string(d.Type)
		}
		prev, cur := m.seen[name], seen{state: r.state, failures: r.failures}
		m.seen[name] = cur
		count := func(key string) { m.o.Count(key) }
		failed := r.failures - prev.failures // attempts that failed since
		switch {
		case cur.state == domain.TunnelConnected && prev.state != domain.TunnelConnected:
			count(telemetry.TunnelKey(typ, telemetry.TunnelConnected))
		case prev.state == domain.TunnelConnected && cur.state != domain.TunnelConnected &&
			cur.state != domain.TunnelDisconnected:
			// It was up and isn't: a drop (whose own increment isn't a
			// failed attempt).
			count(telemetry.TunnelKey(typ, telemetry.TunnelDrop))
			failed--
		}
		if cur.state == domain.TunnelFailed && prev.state != domain.TunnelFailed && prev.state != domain.TunnelConnected {
			if strings.HasPrefix(r.lastErr, "gave up after") {
				count(telemetry.TunnelKey(typ, telemetry.TunnelGaveUp))
			} else if failed <= 0 {
				// A session that ended without connecting, on one attempt
				// (a refusal, a missing engine, a fatal error).
				failed = 1
			}
		}
		for range max(failed, 0) {
			count(telemetry.FailureKey(typ, failureCode(r.lastErr)))
		}
	}
	for name := range m.seen {
		if m.rt[name] == nil {
			delete(m.seen, name)
		}
	}
}

// failureCodes match the messages the user sees — the tunnel's own, fixed
// phrases (diagnose, diagnoseIKE, noHandshake, the refusals) — to the
// report's codes. Only the code is ever counted: the message (with the
// tunnel's name, addresses, log lines) never leaves the machine.
var failureCodes = []struct{ phrase, code string }{
	{"isn't marked for TLS-server use", "eku"},
	{"rejected this profile's certificate", "auth"},
	{"rejected the username or password", "auth"},
	{"hung up right after the login", "auth"},
	{"asks for a username and password, but none", "auth"},
	{"none of the profile's encryption settings", "proposal"},
	{"identified itself differently", "identity"},
	{"doesn't carry the name the profile's RemoteIdentifier", "identity"},
	{"certificate authorities vouch", "cert"},
	{"certificate couldn't be verified", "cert"},
	{"has expired", "cert"},
	{"couldn't read the profile's certificate", "cert"},
	{"couldn't read the profile's private key", "cert"},
	{"encrypted handshake never completed", "tls"},
	{"no handshake with the server", "handshake"},
	{"didn't answer", "unreachable"},
	{"can't reach the server", "unreachable"},
	{"couldn't resolve", "unreachable"},
	{"plugin isn't installed", "plugin"},
	{"couldn't load a part", "plugin"},
	{"web or challenge login", "web_login"},
	{"assigned no address", "no_address"},
	{"; refusing", "addressing"},
	{"isn't installed", "engine"},
	{"is too old", "engine"},
	{"won't run it as root", "engine"},
}

func failureCode(msg string) string {
	for _, f := range failureCodes {
		if strings.Contains(msg, f.phrase) {
			return f.code
		}
	}
	return "other"
}
