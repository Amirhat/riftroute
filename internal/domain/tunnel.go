package domain

import (
	"strings"
	"time"
)

// TunnelType is the protocol a RiftRoute-managed tunnel speaks.
type TunnelType string

// TunnelOpenVPN is an OpenVPN client connection, run by the daemon through the
// system `openvpn` binary with every route/DNS side effect removed.
const TunnelOpenVPN TunnelType = "openvpn"

// TunnelWireGuard is a WireGuard client connection, run inside the daemon
// (wireguard-go) from a wg-quick configuration; its AllowedIPs never become
// routes, and its DNS and hooks are ignored.
const TunnelWireGuard TunnelType = "wireguard"

// TunnelIKEv2 is an IKEv2 connection imported from a configuration profile
// (.mobileconfig), run on strongSwan; the profile's full tunnel, DNS and
// on-demand rules are ignored.
const TunnelIKEv2 TunnelType = "ikev2"

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

// TunnelWhenDown is what happens to a tunnel's destinations while it is down.
type TunnelWhenDown string

const (
	// TunnelFallback lets them take the path they'd take without the
	// tunnel (usually the main VPN). Default.
	TunnelFallback TunnelWhenDown = "fallback"
	// TunnelBlock refuses them while the tunnel should be up but isn't —
	// connecting, reconnecting, or failed until it's disconnected — so
	// nothing meant for the tunnel leaves another way.
	TunnelBlock TunnelWhenDown = "block"
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
	// WhenDown: fallback (default) or block. A client that doesn't send it
	// (one from before it) keeps the tunnel's.
	WhenDown TunnelWhenDown `json:"when_down,omitempty"`
}

// TunnelStatus is a tunnel as reported over the API. It never carries the
// profile text or the password.
type TunnelStatus struct {
	Name        string         `json:"name"`
	Type        TunnelType     `json:"type"`
	Via         TunnelVia      `json:"via"`
	Routes      []string       `json:"routes"`
	AutoConnect bool           `json:"auto_connect"`
	WhenDown    TunnelWhenDown `json:"when_down"`
	// Blocking: its destinations are refused right now — it's set to block
	// and is down while it should be up.
	Blocking    bool   `json:"blocking,omitempty"`
	Username    string `json:"username,omitempty"`
	HasPassword bool   `json:"has_password"`
	// NeedsAuth reports that the profile asks for a username/password.
	NeedsAuth bool `json:"needs_auth"`
	// Servers are the profile's remotes ("host:port/proto").
	Servers []string `json:"servers"`
	// Ignored lists what was removed from the profile on import (pushed-route
	// and DNS directives), so the user can see RiftRoute dropped them.
	Ignored []string `json:"ignored,omitempty"`
	// Blocked are routes left out on the current network, and why (another
	// owner already routes that destination, or nothing would be left of it
	// once what it mustn't carry is kept out).
	Blocked []TunnelBlocked `json:"blocked,omitempty"`
	// Narrowed are routes installed with parts kept out on the current
	// network: what they hold that mustn't go into the tunnel (the router's
	// network, a DNS server, an address RiftRoute probes, a tunnel's server)
	// takes its usual path; the rest goes in.
	Narrowed []TunnelNarrowed `json:"narrowed,omitempty"`
	// Captured are routes installed, but that some traffic still goes past:
	// an include-mode app rule selects an app's (or a user's) traffic to any
	// destination before the routing table is consulted, and sends it into
	// another VPN, to these networks too. (Include rules for destinations
	// yield to a live tunnel's networks; an app's can't.)
	Captured []TunnelBlocked `json:"captured,omitempty"`
	// CertExpires is when the tunnel's login certificate stops working
	// (IKEv2 profiles that log in with one).
	CertExpires *time.Time `json:"cert_expires,omitempty"`
	// Profiles are the tunnel-mode profiles that send their destinations
	// into it (Profile.Tunnel), enabled or not.
	Profiles []TunnelProfileRef `json:"profiles,omitempty"`

	// Unreadable: the saved definition can't be read; the tunnel can only
	// be deleted (and added again).
	Unreadable bool `json:"unreadable,omitempty"`

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

// TunnelNarrowed is a tunnel route installed with parts kept out of it.
type TunnelNarrowed struct {
	Route  string         `json:"route"`
	Except []TunnelExcept `json:"except"`
}

// TunnelExcept is one part kept out of a tunnel route (a network, or one
// address), and why.
type TunnelExcept struct {
	Net    string `json:"net"`
	Reason string `json:"reason"`
}

// TunnelProfileRef is a tunnel-mode profile that sends its destinations
// into a tunnel: what the tunnel's card lists, with the profile's toggle.
type TunnelProfileRef struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Routes is how many destinations it sends in (aggregated); 0 while off.
	Routes int `json:"routes"`
}

// TunnelEngine reports whether the program tunnels run on (openvpn) is
// usable on this machine and, when it isn't, how to install it here. On
// macOS it ships with RiftRoute and is installed with the daemon; on Linux
// the user installs the distribution's package, and the daemon picks it up
// without a restart.
type TunnelEngine struct {
	Available bool   `json:"available"`
	Path      string `json:"path,omitempty"`
	Version   string `json:"version,omitempty"`
	// Problem says why tunnels can't run ("OpenVPN isn't installed", too old,
	// unsafe permissions, unsupported OS); empty when Available.
	Problem string         `json:"problem,omitempty"`
	Install *TunnelInstall `json:"install,omitempty"`
	// IKEv2 is the same report for IKEv2 tunnels' strongSwan (charon-cmd),
	// beside openvpn's; absent from daemons without IKEv2.
	IKEv2 *TunnelEngine `json:"ikev2,omitempty"`
}

// TunnelInstall is how to install (or fix) openvpn on this system: on macOS,
// RiftRoute's own openvpn — an update check installs a missing one, and
// reinstalling the daemon from a current release puts it back; on Linux, the
// distribution's package manager.
type TunnelInstall struct {
	// System names the OS the steps are for ("macOS", "Ubuntu 24.04.1 LTS").
	System string `json:"system"`
	// Action is the kind of fix, for a client that offers it as a button
	// rather than as text. Empty from daemons that predate it.
	Action TunnelInstallAction `json:"action,omitempty"`
	// Commands are run in a terminal, in order; empty when there is no
	// one-line install (Note and URL say what to do instead).
	Commands []string `json:"commands,omitempty"`
	Note     string   `json:"note,omitempty"`
	URL      string   `json:"url,omitempty"`
}

// TunnelInstallAction is what fixes openvpn here (TunnelInstall.Action).
type TunnelInstallAction string

const (
	// TunnelInstallUpdate: RiftRoute's own openvpn (macOS) is missing. The
	// daemon's update check installs the one the newest release ships — even
	// with updates off, as long as the daemon is the installed service — and
	// reinstalling the daemon from a current release puts it in place too.
	TunnelInstallUpdate TunnelInstallAction = "update"
	// TunnelInstallReinstall: RiftRoute's own openvpn (macOS) is there but
	// can't be used. Reinstalling the daemon from a current release replaces
	// it; an update check doesn't touch an openvpn that's present.
	TunnelInstallReinstall TunnelInstallAction = "reinstall"
	// TunnelInstallPackage: the system's openvpn package (Linux) — Commands,
	// Note and URL say how to install, upgrade or reinstall it.
	TunnelInstallPackage TunnelInstallAction = "install"
)

// Summary renders the steps on one line, for errors, logs, and doctor:
// "run `sudo dnf install openvpn`. OpenVPN comes from EPEL on RHEL … https://…".
func (in *TunnelInstall) Summary() string {
	if in == nil {
		return ""
	}
	var parts []string
	if len(in.Commands) > 0 {
		parts = append(parts, "run `"+strings.Join(in.Commands, " && ")+"`.")
	}
	if in.Note != "" {
		parts = append(parts, in.Note)
	}
	if in.URL != "" {
		parts = append(parts, in.URL)
	}
	return strings.Join(parts, " ")
}
