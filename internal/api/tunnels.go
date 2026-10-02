package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Amirhat/riftroute/internal/config"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/tunnel"
)

// TunnelManager is the daemon's tunnel runner (internal/tunnel.Manager).
type TunnelManager interface {
	List() []domain.TunnelStatus
	Status(name string) (domain.TunnelStatus, bool)
	Save(ctx context.Context, spec domain.TunnelSpec) (domain.TunnelStatus, error)
	Delete(ctx context.Context, name string) error
	Connect(name string) error
	Disconnect(ctx context.Context, name string) error
	Log(name string) ([]string, bool)
	Engine() domain.TunnelEngine
}

// handleTunnelEngine reports whether tunnels can run on this machine and, if
// not, how the user installs openvpn here — shown before they try to connect.
func (s *Server) handleTunnelEngine(w http.ResponseWriter, r *http.Request) {
	if !s.tunnelsEnabled(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.tunnels.Engine())
}

// handleTunnelLog returns openvpn's recent output for a tunnel (the running
// session's, else the last one's) — what explains a stuck or failed connect.
func (s *Server) handleTunnelLog(w http.ResponseWriter, r *http.Request) {
	if !s.tunnelsEnabled(w) {
		return
	}
	lines, ok := s.tunnels.Log(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, fmt.Errorf("no tunnel named %q", r.PathValue("name")))
		return
	}
	if lines == nil {
		lines = []string{}
	}
	writeJSON(w, http.StatusOK, map[string][]string{"lines": lines})
}

// SetTunnels installs the tunnel manager (daemon wiring; nil disables the API).
func (s *Server) SetTunnels(m TunnelManager) { s.tunnels = m }

// TunnelResp answers a tunnel save: the saved tunnel plus any warnings, or
// (with a 400) the validation issues.
type TunnelResp struct {
	Tunnel *domain.TunnelStatus `json:"tunnel,omitempty"`
	Issues []config.Issue       `json:"issues,omitempty"`
}

func (s *Server) tunnelsEnabled(w http.ResponseWriter) bool {
	if s.tunnels == nil {
		writeErr(w, http.StatusNotImplemented, errors.New("tunnels are not available on this daemon"))
		return false
	}
	return true
}

func (s *Server) handleTunnels(w http.ResponseWriter, r *http.Request) {
	out := s.svc.TunnelStatuses(r.Context())
	if out == nil && s.tunnels != nil {
		out = s.tunnels.List()
	}
	if out == nil {
		out = []domain.TunnelStatus{}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleTunnelSave(w http.ResponseWriter, r *http.Request) {
	if !s.tunnelsEnabled(w) {
		return
	}
	var spec domain.TunnelSpec
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&spec); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	st, err := s.tunnels.Save(teardownCtx(r), spec)
	var ve *tunnel.ValidationError
	if errors.As(err, &ve) {
		writeJSON(w, http.StatusBadRequest, TunnelResp{Issues: ve.Issues})
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.auditTunnel(r, "tunnel-save", spec.Name, "ok", "")
	s.BroadcastState(r.Context())
	writeJSON(w, http.StatusOK, TunnelResp{Tunnel: &st, Issues: s.tunnelRouteWarnings(r.Context(), st.Name)})
}

// tunnelRouteWarnings says, up front, what of a saved tunnel's routes the
// engine leaves out on the current network, and what it keeps out of them.
func (s *Server) tunnelRouteWarnings(ctx context.Context, name string) []config.Issue {
	var out []config.Issue
	for _, t := range s.svc.TunnelStatuses(ctx) {
		if t.Name != name {
			continue
		}
		for _, b := range t.Blocked {
			out = append(out, config.Issue{
				Severity: config.SevWarning, Field: "routes",
				Msg: fmt.Sprintf("%s isn't installed on this network: %s — the tunnel's other routes are", b.Route, b.Reason),
			})
		}
		for _, n := range t.Narrowed {
			path := "that keeps its"
			if len(n.Except) > 1 {
				path = "those keep their"
			}
			out = append(out, config.Issue{
				Severity: config.SevWarning, Field: "routes",
				Msg: fmt.Sprintf("%s goes in except %s — on this network %s usual path", n.Route, tunnelExceptText(n.Except), path),
			})
		}
	}
	return out
}

// tunnelExceptText lists what was kept out of a route, and why.
func tunnelExceptText(except []domain.TunnelExcept) string {
	var out []string
	for _, e := range except {
		out = append(out, e.Net+" ("+e.Reason+")")
	}
	return strings.Join(out, ", ")
}

func (s *Server) handleTunnelDelete(w http.ResponseWriter, r *http.Request) {
	if !s.tunnelsEnabled(w) {
		return
	}
	name := r.PathValue("name")
	if _, ok := s.tunnels.Status(name); !ok {
		writeErr(w, http.StatusNotFound, fmt.Errorf("no tunnel named %q", name))
		return
	}
	if err := s.tunnels.Delete(teardownCtx(r), name); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.auditTunnel(r, "tunnel-delete", name, "ok", "")
	s.BroadcastState(r.Context())
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleTunnelConnect(connect bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.tunnelsEnabled(w) {
			return
		}
		name := r.PathValue("name")
		if _, ok := s.tunnels.Status(name); !ok {
			writeErr(w, http.StatusNotFound, fmt.Errorf("no tunnel named %q", name))
			return
		}
		action, err := "tunnel-connect", error(nil)
		if connect {
			err = s.tunnels.Connect(name)
		} else {
			action = "tunnel-disconnect"
			err = s.tunnels.Disconnect(teardownCtx(r), name)
		}
		if err != nil {
			s.auditTunnel(r, action, name, "failed", err.Error())
			status := http.StatusInternalServerError
			if errors.Is(err, tunnel.ErrEngineUnavailable) {
				status = http.StatusPreconditionFailed
			}
			writeErr(w, status, err)
			return
		}
		s.auditTunnel(r, action, name, "ok", "")
		st, _ := s.tunnels.Status(name)
		s.BroadcastState(r.Context())
		writeJSON(w, http.StatusOK, st)
	}
}

func (s *Server) auditTunnel(_ *http.Request, action, name, result, reason string) {
	if s.store == nil {
		return
	}
	_, _ = s.store.AppendAudit(domain.AuditEvent{
		Actor: domain.ActorUI, Action: action, Profile: "tunnel:" + name, Result: result, Reason: reason,
	})
}

// teardownCtx is the context for stopping a tunnel on a request's behalf. It
// isn't the request's: a client that gives up waiting mustn't turn a clean
// openvpn shutdown into a kill. It still has a bound.
func teardownCtx(r *http.Request) context.Context {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
	context.AfterFunc(ctx, cancel)
	return ctx
}
