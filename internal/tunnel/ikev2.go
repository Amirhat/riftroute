package tunnel

import (
	"context"

	"github.com/Amirhat/riftroute/internal/domain"
)

// ikev2Driver runs IKEv2 connections from configuration profiles
// (.mobileconfig) on strongSwan's charon (docs/tunnels-ikev2.md).
type ikev2Driver struct{ o *Options }

func (ikev2Driver) parse(config string) (*parsed, error) {
	c, err := ParseMobileconfig(config)
	if err != nil {
		return nil, err
	}
	return &parsed{remotes: []Remote{c.Remote}, servers: c.Servers(), ignored: c.Ignored, ike: c}, nil
}

// errNoIKEv2Engine is why an IKEv2 tunnel can't connect yet: its engine
// (strongSwan) isn't part of this version.
const errNoIKEv2Engine = "IKEv2 tunnels run on strongSwan, which isn't part of this version of RiftRoute yet — the profile is saved, and connects once it is"

func (ikev2Driver) engine() domain.TunnelEngine {
	return domain.TunnelEngine{Problem: errNoIKEv2Engine}
}

func (ikev2Driver) run(_ context.Context, m *Manager, name string, _ *def, _ *parsed, _ *session) {
	m.setErr(name, errNoIKEv2Engine)
}
