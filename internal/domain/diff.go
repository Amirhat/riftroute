package domain

// DiffAction is the kind of change in a desired-vs-actual diff.
type DiffAction string

const (
	DiffAdd    DiffAction = "add"    // present in desired, missing from actual
	DiffDel    DiffAction = "del"    // present in actual (managed), not desired
	DiffChange DiffAction = "change" // present in both but differing
)

// DiffEntry is a single managed-route delta.
type DiffEntry struct {
	Action DiffAction `json:"action"`
	Route  Route      `json:"route"`
}

// Diff is the desired-vs-actual difference over MANAGED routes only (spec §7.3).
// In the read-only core (M1) desired is empty, so a clean system yields InSync.
type Diff struct {
	Entries []DiffEntry `json:"entries"`
	Adds    int         `json:"adds"`
	Dels    int         `json:"dels"`
	Changes int         `json:"changes"`
	InSync  bool        `json:"in_sync"`
}
