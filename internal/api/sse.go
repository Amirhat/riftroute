package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// Hub is a fan-out broadcaster for SSE clients. Slow clients drop events rather
// than block the daemon.
type Hub struct {
	mu      sync.Mutex
	clients map[chan domain.Event]struct{}
}

// NewHub builds an empty Hub.
func NewHub() *Hub { return &Hub{clients: map[chan domain.Event]struct{}{}} }

// Subscribe registers a new client channel.
func (h *Hub) Subscribe() chan domain.Event {
	ch := make(chan domain.Event, 32)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

// Unsubscribe removes and closes a client channel.
func (h *Hub) Unsubscribe(ch chan domain.Event) {
	h.mu.Lock()
	if _, ok := h.clients[ch]; ok {
		delete(h.clients, ch)
		close(ch)
	}
	h.mu.Unlock()
}

// Broadcast delivers ev to all clients (non-blocking; drops to slow clients).
func (h *Hub) Broadcast(ev domain.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- ev:
		default: // slow consumer; skip this event for it
		}
	}
}

// Count returns the number of connected clients.
func (h *Hub) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// BroadcastState builds a fresh State and pushes it to all clients.
func (s *Server) BroadcastState(ctx context.Context) {
	st, err := s.svc.State(ctx)
	if err != nil {
		return
	}
	if ev, err := domain.NewEvent(domain.EventState, time.Now(), st); err == nil {
		s.hub.Broadcast(ev)
	}
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, errStreamingUnsupported)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	ch := s.hub.Subscribe()
	defer s.hub.Unsubscribe(ch)

	// Greet, then send the current state so a fresh client renders immediately.
	if ev, err := domain.NewEvent(domain.EventHello, time.Now(), map[string]string{"version": s.version}); err == nil {
		writeSSE(w, ev)
	}
	s.BroadcastState(r.Context()) // also delivered to this client via the hub
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			writeSSE(w, ev)
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, ev domain.Event) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	// SSE frame: a single data line carrying the JSON envelope.
	_, _ = w.Write([]byte("data: "))
	_, _ = w.Write(b)
	_, _ = w.Write([]byte("\n\n"))
}
