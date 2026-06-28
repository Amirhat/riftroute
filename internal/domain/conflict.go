package domain

// Conflict is an overlap/shadow between managed routes that would route the same
// destination two different ways (spec §7.8). Surfaced so the operator is never
// surprised by which rule actually wins (longest-prefix-match).
type Conflict struct {
	Kind   string `json:"kind"` // "duplicate" | "shadowed" | "overlap"
	A      string `json:"a"`    // "<cidr> (<profile>)"
	B      string `json:"b"`
	Detail string `json:"detail"`
}
