package domain

// RouteExplain is the answer to "where does traffic to X go, and why?" — the
// killer debugging tool (spec §7.2). It shows the kernel's real decision next to
// RiftRoute's simulated decision over desired state and flags any drift.
type RouteExplain struct {
	Target string `json:"target"`
	// Resolved holds the A/AAAA addresses when Target was a domain.
	Resolved []string `json:"resolved,omitempty"`
	// Kernel is the kernel's real answer (route get / ip route get).
	Kernel RouteDecision `json:"kernel"`
	// Simulated is RiftRoute's answer over desired state. Nil until the routing
	// engine lands (M1+); when present and != Kernel, Drift is true.
	Simulated *RouteDecision `json:"simulated,omitempty"`
	Drift     bool           `json:"drift"`
	Note      string         `json:"note,omitempty"`
}
