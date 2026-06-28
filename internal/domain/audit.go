package domain

import "time"

// Snapshot is a full captured network state, restorable (spec §2.1).
type Snapshot struct {
	ID        string         `json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	Reason    string         `json:"reason"`
	RoutesV4  []Route        `json:"routes_v4"`
	RoutesV6  []Route        `json:"routes_v6"`
	Rules     []PolicyRule   `json:"rules,omitempty"`
	Defaults  []DefaultRoute `json:"defaults"`
	DNS       DNSState       `json:"dns"`
}

// OpKind is the kind of a single plan operation.
type OpKind string

const (
	OpAddRoute OpKind = "add_route"
	OpDelRoute OpKind = "del_route"
	OpAddRule  OpKind = "add_rule"
	OpDelRule  OpKind = "del_rule"
)

// PlanOp is one ordered operation in a transaction. Command is the exact
// arg-array that will be exec'd (no shell), shown verbatim in dry-run and audit.
type PlanOp struct {
	Kind    OpKind        `json:"kind"`
	Route   *ManagedRoute `json:"route,omitempty"`
	Rule    *ManagedRule  `json:"rule,omitempty"`
	Command []string      `json:"command"`
	Human   string        `json:"human"`
}

// Plan is an ordered set of ops plus its precomputed inverse (spec §2.2).
type Plan struct {
	Ops     []PlanOp `json:"ops"`
	Inverse []PlanOp `json:"inverse"`
}

// TxResult is the outcome of a transaction.
type TxResult string

const (
	TxPending    TxResult = "pending"
	TxCommitted  TxResult = "committed"
	TxRolledBack TxResult = "rolled_back"
	TxFailed     TxResult = "failed"
)

// Transaction is a planned-and-applied (or rolled-back) mutation.
type Transaction struct {
	ID     string   `json:"id"`
	Plan   Plan     `json:"plan"`
	Result TxResult `json:"result"`
	Error  string   `json:"error,omitempty"`
}

// Actor is who initiated an action (spec §5.1).
type Actor string

const (
	ActorUI     Actor = "ui"
	ActorCLI    Actor = "cli"
	ActorDaemon Actor = "daemon-auto"
	ActorSystem Actor = "system"
)

// AuditEvent records every change with the exact commands run (spec §7.7).
type AuditEvent struct {
	ID       int64     `json:"id"`
	TS       time.Time `json:"ts"`
	Actor    Actor     `json:"actor"`
	Action   string    `json:"action"`
	Profile  string    `json:"profile,omitempty"`
	Plan     *Plan     `json:"plan,omitempty"`
	Result   string    `json:"result"`
	Rollback bool      `json:"rollback,omitempty"`
	Reason   string    `json:"reason,omitempty"`
}
