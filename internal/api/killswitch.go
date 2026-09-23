package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/killswitch"
)

// killSwitchConfig derives what the kill switch lets user apps reach outside
// the tunnel from live state (see killswitch.Derive).
func (s *Server) killSwitchConfig(ctx context.Context) killswitch.Config {
	ifaces, _ := s.svc.Interfaces(ctx)
	var gw netip.Addr
	if g, _, err := s.svc.Provider().DefaultGateway(ctx, domain.FamilyV4); err == nil {
		gw = g
	}
	var owned []domain.ManagedRoute
	if s.store != nil {
		owned, _ = s.store.ListOwned()
	}
	return killswitch.Derive(ifaces, gw, owned)
}

func (s *Server) handleKillSwitch(w http.ResponseWriter, r *http.Request) {
	if s.killSwitch == nil {
		writeErr(w, http.StatusNotImplemented, errors.New("kill switch unavailable"))
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.ksMu.Lock()
	var err error
	if req.Enabled {
		cfg := s.killSwitchConfig(r.Context())
		if err = s.killSwitch.Enable(r.Context(), cfg); err == nil {
			s.ksWant, s.ksLast = true, cfg
		}
	} else if err = s.killSwitch.Disable(r.Context()); err == nil {
		s.ksWant = false
	}
	s.ksMu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	on, _ := s.killSwitch.Enabled(r.Context())
	s.BroadcastState(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"kill_switch": on, "backend": s.killSwitch.Backend()})
}

// InitKillSwitch runs once at daemon start. A kill switch in force stays on
// — re-rendered with the current rules and then kept in sync. Rules that are
// loaded but were never enforced (the macOS state before this fix: an anchor
// pf.conf didn't reference) are cleared rather than suddenly enforced on
// upgrade; the user turns it on again knowingly.
func (s *Server) InitKillSwitch(ctx context.Context) {
	if s.killSwitch == nil {
		return
	}
	st := s.killSwitch.Status(ctx)
	s.ksMu.Lock()
	defer s.ksMu.Unlock()
	switch {
	case st.Effective:
		s.ksWant = true
		cfg := s.killSwitchConfig(ctx)
		if err := s.killSwitch.Enable(ctx, cfg); err != nil {
			s.log.Warn("kill switch: re-applying on startup failed", "err", err)
			return
		}
		s.ksLast = cfg
		s.log.Info("kill switch on; keeping it in sync")
	case st.Loaded:
		if err := s.killSwitch.Disable(ctx); err != nil {
			s.log.Warn("kill switch: clearing never-enforced rules failed", "err", err)
			return
		}
		s.log.Warn("kill switch rules were loaded but never enforced (pf anchor not referenced); cleared — turn the kill switch on again to use it")
	}
}

// ksVerifyEvery: every Nth sync also checks the kill switch is still in force
// (a VPN client or admin reloading pf.conf can drop our hook).
const ksVerifyEvery = 10

// SyncKillSwitch re-renders the kill switch when what it must allow changed —
// a VPN came back on a new interface, the gateway moved, profiles changed the
// bypass set — so reconnecting VPNs and exclude routes are never fenced by a
// stale list. The daemon calls it every few seconds; it's a no-op while off.
func (s *Server) SyncKillSwitch(ctx context.Context) {
	if s.killSwitch == nil {
		return
	}
	s.ksMu.Lock()
	defer s.ksMu.Unlock()
	if !s.ksWant {
		return
	}
	s.ksTick++
	cfg := s.killSwitchConfig(ctx)
	lost := s.ksTick%ksVerifyEvery == 0 && !s.killSwitch.Status(ctx).Effective
	if cfg.Equal(s.ksLast) && !lost {
		return
	}
	if err := s.killSwitch.Enable(ctx, cfg); err != nil {
		s.log.Warn("kill switch re-sync failed", "err", err)
		return
	}
	s.ksLast = cfg
	s.log.Info("kill switch re-synced", "tunnels", cfg.TunnelIfaces, "bypass", len(cfg.Bypass), "reasserted", lost)
}

// disableKillSwitch turns the kill switch off (panic: restore the baseline).
func (s *Server) disableKillSwitch(ctx context.Context) {
	if s.killSwitch == nil {
		return
	}
	s.ksMu.Lock()
	defer s.ksMu.Unlock()
	if err := s.killSwitch.Disable(ctx); err != nil {
		s.log.Warn("panic: could not turn the kill switch off", "err", err)
		return
	}
	s.ksWant = false
}
