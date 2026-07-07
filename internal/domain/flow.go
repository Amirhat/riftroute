package domain

// Flow is an active connection correlated to the route that carries it — the
// answer to "is THIS actually going through the tunnel?" (spec §7.4).
type Flow struct {
	Proto   string `json:"proto"` // tcp | udp
	Local   string `json:"local"`
	Remote  string `json:"remote"`
	State   string `json:"state,omitempty"`
	Process string `json:"process,omitempty"`
	PID     string `json:"pid,omitempty"`
	Iface   string `json:"iface,omitempty"`
	ViaVPN  bool   `json:"via_vpn"`
}
