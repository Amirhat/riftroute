// Package domain holds the core entities shared across the daemon, CLI, and
// desktop app. These types are the wire contract: they are serialized to JSON
// over the UDS API and (via Wails) generate the TypeScript bindings the React
// frontend consumes. To keep the contract language-agnostic and WebKit/TS
// friendly, IP/CIDR fields are plain strings here; the routing engine parses
// them into net/netip values internally.
package domain

// Family is an IP address family.
type Family string

const (
	FamilyV4 Family = "v4"
	FamilyV6 Family = "v6"
)

// Owner classifies who installed a route. RiftRoute only ever mutates routes it
// owns (spec §2.3); classification of foreign routes is best-effort.
type Owner string

const (
	OwnerSystem    Owner = "system"
	OwnerRiftRoute Owner = "riftroute"
	OwnerVPN       Owner = "vpn"
	OwnerUnknown   Owner = "unknown"
)

// Route is a kernel route as read from the routing table.
type Route struct {
	DstCIDR string `json:"dst_cidr"`
	Gateway string `json:"gateway,omitempty"`
	Iface   string `json:"iface"`
	Metric  int    `json:"metric"`
	Family  Family `json:"family"`
	Owner   Owner  `json:"owner"`
	// Proto is the Linux route protocol tag (e.g. "riftroute", "kernel",
	// "dhcp"). Empty on macOS, which has no proto field.
	Proto string `json:"proto,omitempty"`
	// Profile is the owning profile id for managed routes; empty otherwise.
	Profile string `json:"profile,omitempty"`
}

// PolicyRule is a Linux `ip rule` entry (Model B). Empty set on macOS, which
// has no policy-routing tables.
type PolicyRule struct {
	Priority int    `json:"priority"`
	Selector string `json:"selector"` // e.g. "to 10.0.0.0/8" / "from 192.0.2.0/24"
	Table    string `json:"table"`
	Family   Family `json:"family"`
	Proto    string `json:"proto,omitempty"`
}

// IfaceKind is a coarse classification of a network interface.
type IfaceKind string

const (
	IfaceKindPhysical IfaceKind = "phys"
	IfaceKindUtun     IfaceKind = "utun"
	IfaceKindTun      IfaceKind = "tun"
	IfaceKindWG       IfaceKind = "wg"
	IfaceKindBridge   IfaceKind = "bridge"
	IfaceKindLoopback IfaceKind = "loopback"
	IfaceKindOther    IfaceKind = "other"
)

// Iface is a network interface as observed by the provider.
type Iface struct {
	Name  string    `json:"name"`
	Up    bool      `json:"up"`
	Kind  IfaceKind `json:"kind"`
	Addrs []string  `json:"addrs"`
	MTU   int       `json:"mtu,omitempty"`
	// IsVPN is true for tunnel interfaces (utun/tun/wg) that are candidates
	// for carrying VPN traffic.
	IsVPN bool `json:"is_vpn"`
}

// DNSState is the resolver configuration in effect.
type DNSState struct {
	Servers       []string `json:"servers"`
	SearchDomains []string `json:"search_domains,omitempty"`
	Iface         string   `json:"iface,omitempty"`
}

// DefaultRoute is the default route for one family and who owns it.
type DefaultRoute struct {
	Family  Family `json:"family"`
	Present bool   `json:"present"`
	Gateway string `json:"gateway,omitempty"`
	Iface   string `json:"iface,omitempty"`
	Owner   Owner  `json:"owner"`
	// ViaVPN indicates the default route currently points at a tunnel.
	ViaVPN bool `json:"via_vpn"`
}

// RouteDecision is the answer to "where does traffic to X go?" — produced both
// by the kernel (route get / ip route get) and by RiftRoute's simulator, so the
// UI can show both and highlight drift (spec §7.2).
type RouteDecision struct {
	Target      string `json:"target"`
	Source      string `json:"source"` // "kernel" | "simulated"
	MatchedCIDR string `json:"matched_cidr,omitempty"`
	Gateway     string `json:"gateway,omitempty"`
	Iface       string `json:"iface"`
	Family      Family `json:"family"`
	Owner       Owner  `json:"owner,omitempty"`
	Profile     string `json:"profile,omitempty"`
	ViaVPN      bool   `json:"via_vpn"`
	// Reachable is false when no matching route exists (blackhole/unreachable).
	Reachable bool `json:"reachable"`
}

// Capabilities lets the UI honestly enable/disable features the OS can't do
// (spec §4.1). macOS lacks policy routing, fwmark, per-app routing, and a route
// proto tag; Linux has all of them.
type Capabilities struct {
	Platform      string `json:"platform"`       // "darwin" | "linux" | "fake" | "unsupported"
	PolicyRouting bool   `json:"policy_routing"` // Model B (dedicated table + ip rule)
	Fwmark        bool   `json:"fwmark"`
	PerAppRouting bool   `json:"per_app_routing"`
	ProtoTag      bool   `json:"proto_tag"` // ownership via route proto (Linux)
	IPv6          bool   `json:"ipv6"`
	KillSwitch    bool   `json:"kill_switch"`
	IfaceScoping  bool   `json:"iface_scoping"` // macOS -ifscope
}
