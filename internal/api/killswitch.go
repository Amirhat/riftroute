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
	var (
		gw      netip.Addr
		uplinks []string
	)
	if g, ifn, err := s.svc.Provider().DefaultGateway(ctx, domain.FamilyV4); err == nil {
		gw, uplinks = g, append(uplinks, ifn)
	}
	// The IPv6 default can leave through a different interface than IPv4.
	if _, ifn, err := s.svc.Provider().DefaultGateway(ctx, domain.FamilyV6); err == nil {
		uplinks = append(uplinks, ifn)
	}
	var owned []domain.ManagedRoute
	if s.store != nil {
		owned, _ = s.store.ListOwned()
	}
	return killswitch.Derive(ifaces, gw, uplinks, owned)
}

// killSwitchKey persists the user's on/off choice: rules don't survive a
// reboot (pf anchors and nftables live in the kernel), so the daemon restores
// them from this at startup.
const killSwitchKey = "kill_switch"

func (s *Server) persistKillSwitch(on bool) {
	if s.store == nil {
		return
	}
	v := "false"
	if on {
		v = "true"
	}
	if err := s.store.SetSetting(killSwitchKey, v); err != nil {
		s.log.Warn("kill switch choice not persisted", "err", err)
	}
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
			s.persistKillSwitch(true)
		}
	} else if err = s.killSwitch.Disable(r.Context()); err == nil {
		s.ksWant = false
		s.persistKillSwitch(false)
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

// InitKillSwitch runs once at daemon start and restores the user's saved
// choice — kernel rules don't survive a reboot, and apps start at login before
// the VPN connects. Saved "on": (re)applied with current rules (if that fails
// now, e.g. no network yet, the re-sync keeps trying). Otherwise, rules still
// loaded (the pre-fix macOS anchor nothing referenced, which never saved a
// choice) are cleared rather than suddenly enforced.
func (s *Server) InitKillSwitch(ctx context.Context) {
	if s.killSwitch == nil {
		return
	}
	want := false
	if s.store != nil {
		v, _, _ := s.store.GetSetting(killSwitchKey)
		want = v == "true"
	}
	s.ksMu.Lock()
	defer s.ksMu.Unlock()
	if want {
		s.ksWant = true
		cfg := s.killSwitchConfig(ctx)
		if err := s.killSwitch.Enable(ctx, cfg); err != nil {
			s.log.Warn("kill switch: restoring on startup failed; will keep retrying", "err", err)
			return
		}
		s.ksLast = cfg
		s.log.Info("kill switch restored on startup")
		return
	}
	switch st := s.killSwitch.Status(ctx); {
	case st.Effective:
		// In force without a saved choice: a previous version that never
		// persisted it (Linux's nftables table was always enforced). Keep it.
		s.ksWant = true
		s.persistKillSwitch(true)
		cfg := s.killSwitchConfig(ctx)
		if err := s.killSwitch.Enable(ctx, cfg); err == nil {
			s.ksLast = cfg
		}
		s.log.Info("kill switch in force from a previous version; kept on")
		return
	case st.Loaded:
		if err := s.killSwitch.Disable(ctx); err != nil {
			s.log.Warn("kill switch: clearing leftover rules failed", "err", err)
			return
		}
		s.log.Warn("kill switch rules were loaded but not enforced (the old unreferenced macOS anchor); cleared — turn the kill switch on again to use it")
	}
}

// SyncKillSwitch re-renders the kill switch when what it guards or allows
// changed (an interface came up, the gateway moved, profiles changed the
// bypass set), and re-asserts it when something dropped it (a VPN client or
// admin reloading pf.conf, `pfctl -d`). The daemon calls it every few seconds
// (Status is cached, so the check is cheap); it's a no-op while off.
func (s *Server) SyncKillSwitch(ctx context.Context) {
	if s.killSwitch == nil {
		return
	}
	s.ksMu.Lock()
	defer s.ksMu.Unlock()
	if !s.ksWant {
		return
	}
	cfg := s.killSwitchConfig(ctx)
	if cfg.Empty() {
		return // no uplink right now (e.g. Wi-Fi off): keep the last rules
	}
	lost := !s.killSwitch.Status(ctx).Effective
	if cfg.Equal(s.ksLast) && !lost {
		return
	}
	if err := s.killSwitch.Enable(ctx, cfg); err != nil {
		s.log.Warn("kill switch re-sync failed", "err", err)
		return
	}
	s.ksLast = cfg
	s.log.Info("kill switch re-synced", "guarding", cfg.PhysIfaces, "bypass", len(cfg.Bypass), "reasserted", lost)
}

// disableKillSwitch turns the kill switch off and records that choice (panic:
// back to the baseline). The wanted state is dropped even if removal fails,
// so the re-sync never puts it back.
func (s *Server) disableKillSwitch(ctx context.Context) error {
	if s.killSwitch == nil {
		return nil
	}
	s.ksMu.Lock()
	defer s.ksMu.Unlock()
	s.ksWant = false
	s.persistKillSwitch(false)
	return s.killSwitch.Disable(ctx)
}
