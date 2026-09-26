package api

import (
	"net/http"

	"github.com/Amirhat/riftroute/internal/domain"
)

// Updater is the daemon's update state machine as the API sees it.
type Updater interface {
	Status() domain.UpdateStatus
	// CheckNow and InstallNow work on the daemon's own lifetime and return
	// once the verdict is known (or after a few seconds); clients follow the
	// rest through GET /update or State.
	CheckNow() domain.UpdateStatus
	InstallNow() (domain.UpdateStatus, error)
	RequestRollback() error
}

// SetUpdater wires the updater (nil: the update endpoints answer 503).
func (s *Server) SetUpdater(u Updater) { s.updater = u }

func (s *Server) routesUpdate() {
	s.mux.HandleFunc("GET /update", s.handleUpdateStatus)
	// A check only reads (and at most stages a verified download), but it
	// makes network requests on the user's behalf: writers only.
	s.mux.HandleFunc("POST /update/check", s.requireWrite(s.handleUpdateCheck))
	s.mux.HandleFunc("POST /update/install", s.requireWrite(s.handleUpdateInstall))
	s.mux.HandleFunc("POST /update/rollback", s.requireWrite(s.handleUpdateRollback))
}

func (s *Server) updaterOr503(w http.ResponseWriter) Updater {
	if s.updater == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "this daemon has no updater"})
	}
	return s.updater
}

func (s *Server) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if u := s.updaterOr503(w); u != nil {
		writeJSON(w, http.StatusOK, u.Status())
	}
}

func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if u := s.updaterOr503(w); u != nil {
		writeJSON(w, http.StatusOK, u.CheckNow())
	}
}

func (s *Server) handleUpdateInstall(w http.ResponseWriter, r *http.Request) {
	u := s.updaterOr503(w)
	if u == nil {
		return
	}
	st, err := u.InstallNow()
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "status": st})
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleUpdateRollback(w http.ResponseWriter, r *http.Request) {
	u := s.updaterOr503(w)
	if u == nil {
		return
	}
	if err := u.RequestRollback(); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "rolling back; the daemon restarts into the previous version"})
}
