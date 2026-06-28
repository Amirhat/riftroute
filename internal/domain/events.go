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
)

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
