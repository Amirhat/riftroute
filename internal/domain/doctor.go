package domain

import "time"

// CheckStatus is the outcome of one diagnostic check.
type CheckStatus string

const (
	CheckPass CheckStatus = "pass"
	CheckWarn CheckStatus = "warn"
	CheckFail CheckStatus = "fail"
)

// DoctorCheck is one diagnostic result with a plain-language fix (spec §7.9).
type DoctorCheck struct {
	Name   string      `json:"name"`
	Status CheckStatus `json:"status"`
	Detail string      `json:"detail"`
	Fix    string      `json:"fix,omitempty"`
}

// DoctorReport is the full diagnostics battery — designed to paste into a bug
// report (spec §7.9/§16).
type DoctorReport struct {
	Checks      []DoctorCheck `json:"checks"`
	Pass        int           `json:"pass"`
	Warn        int           `json:"warn"`
	Fail        int           `json:"fail"`
	OK          bool          `json:"ok"`
	GeneratedAt time.Time     `json:"generated_at"`
}

// Leak is a detected (or suspected) traffic/DNS leak (spec §7.6).
type Leak struct {
	Kind     string `json:"kind"`     // "ipv6" | "dns" | "egress"
	Severity string `json:"severity"` // "warn" | "fail"
	Detail   string `json:"detail"`
}
