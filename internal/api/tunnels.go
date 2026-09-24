package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"

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
	st, err := s.tunnels.Save(r.Context(), spec)
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
	writeJSON(w, http.StatusOK, TunnelResp{Tunnel: &st, Issues: s.tunnelRouteWarnings(r.Context(), st.Routes)})
}

// tunnelRouteWarnings flags routes that contain the router of the current
// network: the engine leaves those out here, so say it up front.
func (s *Server) tunnelRouteWarnings(ctx context.Context, routes []string) []config.Issue {
	var out []config.Issue
	gw, _, err := s.svc.Provider().DefaultGateway(ctx, domain.FamilyV4)
	if err != nil || !gw.IsValid() {
		return nil
	}
	for _, v := range routes {
		pfx, err := netip.ParsePrefix(v)
		if err != nil {
			continue // a host route can't contain the gateway unless it IS it
		}
		if pfx.Contains(gw) {
			out = append(out, config.Issue{
				Severity: config.SevWarning, Field: "routes",
				Msg: fmt.Sprintf("%s contains your router (%s), so it isn't installed while you're on this network — the tunnel's other routes are", v, gw),
			})
		}
	}
	return out
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
	if err := s.tunnels.Delete(r.Context(), name); err != nil {
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
			err = s.tunnels.Disconnect(r.Context(), name)
		}
		if err != nil {
			s.auditTunnel(r, action, name, "failed", err.Error())
			status := http.StatusInternalServerError
			if errors.Is(err, tunnel.ErrNoOpenVPN) {
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
