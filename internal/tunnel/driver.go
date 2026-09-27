package tunnel

import (
	"context"

	"github.com/Amirhat/riftroute/internal/domain"
)

// A driver runs one protocol's connections for the Manager (see
// docs/tunnels-wireguard.md). Everything else — definitions and secrets,
// the state machine, pinning the servers, applying routes, vetting the
// tunnel's addressing, resume after a restart — is the Manager's.
type driver interface {
	// parse checks a definition's config.
	parse(config string) (*parsed, error)
	// engine says whether connections can run here, and how to fix it.
	engine() domain.TunnelEngine
	// run is one session, from resolving its servers to its end. It
	// reports through the Manager (update, setErr, requestApply, …) and
	// returns when the session is over; the Manager's finish records that.
	run(ctx context.Context, m *Manager, name string, d *def, p *parsed, s *session)
}

// parsed is a definition's config as its driver read it: what the Manager
// shows and pins, and the driver's own form.
type parsed struct {
	remotes []Remote // to resolve and pin (via direct)
	servers []string // for display
	ignored []string // what was dropped because RiftRoute owns its job
	// needsAuth: the connection logs in with a username and password, which
	// the config may carry inline.
	needsAuth              bool
	inlineUser, inlinePass string

	ovpn *Profile
	wg   *WGConfig
}

// ovpnDriver runs OpenVPN connections: an openvpn process per session,
// supervised through its management socket (Manager.runOpenVPN). It reads
// the launcher from the Manager's options when it needs it.
type ovpnDriver struct{ o *Options }

func (o ovpnDriver) parse(config string) (*parsed, error) {
	p, err := Parse(config)
	if err != nil {
		return nil, err
	}
	return &parsed{
		remotes: p.Remotes, servers: p.Servers(), ignored: p.Ignored,
		needsAuth: p.NeedsAuth, inlineUser: p.InlineUser, inlinePass: p.InlinePass,
		ovpn: p,
	}, nil
}

func (o ovpnDriver) engine() domain.TunnelEngine { return o.o.Launcher.Engine() }

func (o ovpnDriver) run(ctx context.Context, m *Manager, name string, d *def, p *parsed, s *session) {
	m.runOpenVPN(ctx, name, d, p.ovpn, s)
}
