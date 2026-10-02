package api

import (
	"context"
	"net/http"

	"github.com/Amirhat/riftroute/internal/telemetry"
)

// Telemetry is the daemon's report sender as the API sees it.
type Telemetry interface {
	// Preview is the exact report that would go now, and the last one sent.
	Preview(ctx context.Context) (telemetry.Preview, error)
	// MarkNoticeSeen records that the user has been told about telemetry.
	MarkNoticeSeen() error
}

// SetTelemetry wires the report sender (nil: the endpoints answer 503).
func (s *Server) SetTelemetry(t Telemetry) { s.telemetry = t }

func (s *Server) routesTelemetry() {
	// Readers too: it's what leaves this machine, and nothing else.
	s.mux.HandleFunc("GET /telemetry", s.handleTelemetryPreview)
	s.mux.HandleFunc("POST /telemetry/notice", s.requireWrite(s.handleTelemetryNotice))
}

func (s *Server) telemetryOr503(w http.ResponseWriter) Telemetry {
	if s.telemetry == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "this daemon has no telemetry"})
	}
	return s.telemetry
}

func (s *Server) handleTelemetryPreview(w http.ResponseWriter, r *http.Request) {
	t := s.telemetryOr503(w)
	if t == nil {
		return
	}
	p, err := t.Preview(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleTelemetryNotice(w http.ResponseWriter, r *http.Request) {
	t := s.telemetryOr503(w)
	if t == nil {
		return
	}
	if err := t.MarkNoticeSeen(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.BroadcastState(r.Context())
	w.WriteHeader(http.StatusNoContent)
}
