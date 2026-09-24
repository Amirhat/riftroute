package domain

import "time"

// TunnelType is the protocol a RiftRoute-managed tunnel speaks.
type TunnelType string

// TunnelOpenVPN is an OpenVPN client connection, run by the daemon through the
// system `openvpn` binary with every route/DNS side effect removed.
const TunnelOpenVPN TunnelType = "openvpn"

// TunnelVia is how a managed tunnel reaches its own server.
type TunnelVia string

const (
	// TunnelViaDirect pins the server's address to the physical gateway, so the
	// tunnel's own connection bypasses any other VPN that owns the default
	// route. Default.
	TunnelViaDirect TunnelVia = "direct"
	// TunnelViaDefault follows the system default route — through the other
	// VPN when one is up (a tunnel inside a tunnel).
	TunnelViaDefault TunnelVia = "default"
)

// TunnelState is a managed tunnel's connection state.
type TunnelState string

const (
	TunnelDisconnected TunnelState = "disconnected"
	TunnelConnecting   TunnelState = "connecting"
	TunnelConnected    TunnelState = "connected"
	TunnelReconnecting TunnelState = "reconnecting"
	TunnelFailed       TunnelState = "failed"
)

// TunnelSpec is a tunnel definition as submitted by a client (create/update).
// Config and Password are write-only: an update that leaves them empty keeps
// the stored values, and they are never returned over the API.
type TunnelSpec struct {
	Name     string     `json:"name"`
	Type     TunnelType `json:"type"`
	Config   string     `json:"config,omitempty"` // .ovpn text with every file inlined
	Username string     `json:"username,omitempty"`
	Password string     `json:"password,omitempty"`
	Via      TunnelVia  `json:"via"`
	// Routes are the CIDR/IP destinations sent into the tunnel while it is
	// connected. Nothing else is: the server's redirect-gateway, pushed routes
	// and pushed DNS are all ignored.
	Routes      []string `json:"routes"`
	AutoConnect bool     `json:"auto_connect"`
}

// TunnelStatus is a tunnel as reported over the API. It never carries the
// profile text or the password.
type TunnelStatus struct {
	Name        string     `json:"name"`
	Type        TunnelType `json:"type"`
	Via         TunnelVia  `json:"via"`
	Routes      []string   `json:"routes"`
	AutoConnect bool       `json:"auto_connect"`
	Username    string     `json:"username,omitempty"`
	HasPassword bool       `json:"has_password"`
	// NeedsAuth reports that the profile asks for a username/password.
	NeedsAuth bool `json:"needs_auth"`
	// Servers are the profile's remotes ("host:port/proto").
	Servers []string `json:"servers"`
	// Ignored lists what was removed from the profile on import (pushed-route
	// and DNS directives), so the user can see RiftRoute dropped them.
	Ignored []string `json:"ignored,omitempty"`
	// Blocked are routes left out on the current network, and why (they
	// contain its router, or another owner already routes that destination).
	Blocked []TunnelBlocked `json:"blocked,omitempty"`

	State TunnelState `json:"state"`
	// Detail is the OpenVPN phase while connecting ("auth", "get_config", …)
	// or the reason for a reconnect.
	Detail    string     `json:"detail,omitempty"`
	Iface     string     `json:"iface,omitempty"`
	LocalIP   string     `json:"local_ip,omitempty"`
	Server    string     `json:"server,omitempty"` // the remote actually in use
	Since     *time.Time `json:"since,omitempty"`  // when it last connected
	LastError string     `json:"last_error,omitempty"`
	BytesIn   uint64     `json:"bytes_in"`
	BytesOut  uint64     `json:"bytes_out"`
}

// TunnelBlocked is a tunnel route that isn't installed here, and why.
type TunnelBlocked struct {
	Route  string `json:"route"`
	Reason string `json:"reason"`
}
