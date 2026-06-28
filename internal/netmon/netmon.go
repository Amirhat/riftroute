// Package netmon is the network event monitor (spec §4.5): it emits debounced
// events the reconciler subscribes to so RiftRoute can auto-apply when the VPN
// goes up/down or the network changes. The default implementation (Poller)
// detects changes by diffing successive RouteProvider snapshots, so it works
// uniformly across macOS, Linux, and the fake backend without fragile parsing
// of `route monitor` / `ip monitor` streams (those remain a future optimization).
package netmon

import (
	"sync"
	"time"
)

// EventType identifies a network change (spec §4.5).
type EventType string

const (
	EventVPNUp               EventType = "vpn_up"
	EventVPNDown             EventType = "vpn_down"
	EventDefaultRouteChanged EventType = "default_route_changed"
	EventLinkChanged         EventType = "link_changed"
	EventAddrChanged         EventType = "addr_changed"
	EventDNSChanged          EventType = "dns_changed"
	EventWake                EventType = "wake"
)

// Event is a single observed network change.
type Event struct {
	Type   EventType `json:"type"`
	Iface  string    `json:"iface,omitempty"`
	Detail string    `json:"detail,omitempty"`
	TS     time.Time `json:"ts"`
}

// Monitor emits network events until its context is canceled.
type Monitor interface {
	Events() <-chan Event
}

// FakeMonitor is a programmable monitor for tests: Emit pushes events to
// subscribers deterministically.
type FakeMonitor struct {
	mu  sync.Mutex
	out chan Event
}

// NewFakeMonitor returns a fake monitor with a buffered event channel.
func NewFakeMonitor() *FakeMonitor { return &FakeMonitor{out: make(chan Event, 64)} }

func (m *FakeMonitor) Events() <-chan Event { return m.out }

// Emit pushes an event (non-blocking; drops if the buffer is full).
func (m *FakeMonitor) Emit(e Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case m.out <- e:
	default:
	}
}
