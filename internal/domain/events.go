package domain

import (
	"encoding/json"
	"time"
)

// EventType identifies a server-pushed event delivered over SSE (and re-emitted
// to the React layer as a Wails runtime event — spec §3.5/§11).
type EventType string

const (
	// EventHello is sent once when an SSE client connects.
	EventHello EventType = "hello"
	// EventState carries a fresh State snapshot.
	EventState EventType = "state"
	// EventDrift signals that desired != actual (reconciliation pending).
	EventDrift EventType = "drift"
	// EventApplied / EventRolledBack report mutation outcomes (M2+).
	EventApplied    EventType = "applied"
	EventRolledBack EventType = "rolled_back"
	// EventAudit is appended whenever a new audit entry is written.
	EventAudit EventType = "audit"
	// EventApplyProgress is a step of a change a client asked for and is
	// waiting on (ApplyProgress).
	EventApplyProgress EventType = "apply_progress"
)

// ApplyStep is where a change is on its way to the kernel.
type ApplyStep string

const (
	// StepWaiting: another change is being made; this one goes next.
	StepWaiting ApplyStep = "waiting"
	// StepResolving: looking up the profiles' domain names (Done of Total).
	StepResolving ApplyStep = "resolving"
	// StepChecking: working out what changes, and checking it's safe.
	StepChecking ApplyStep = "checking"
	// StepApplying: changing routes (Done of Total).
	StepApplying ApplyStep = "applying"
)

// ApplyProgress is a step of the change a client tagged with ID (the
// X-RR-Progress request header), so it can show what's happening while it
// waits. Done and Total count the step's items where it has them.
type ApplyProgress struct {
	ID    string    `json:"id"`
	Step  ApplyStep `json:"step"`
	Done  int       `json:"done,omitempty"`
	Total int       `json:"total,omitempty"`
}

// Event is the envelope for everything pushed on the SSE stream. Data is the
// type-specific payload (e.g. a State for EventState).
type Event struct {
	Type EventType       `json:"type"`
	TS   time.Time       `json:"ts"`
	Data json.RawMessage `json:"data,omitempty"`
}

// NewEvent builds an Event with the given payload marshaled into Data.
func NewEvent(t EventType, ts time.Time, payload any) (Event, error) {
	e := Event{Type: t, TS: ts}
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return Event{}, err
		}
		e.Data = b
	}
	return e, nil
}
