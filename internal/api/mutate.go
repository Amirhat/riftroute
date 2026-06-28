package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/Amirhat/riftroute/internal/config"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/killswitch"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/store"
)

type applyReq struct {
	DryRun            bool `json:"dry_run"`
	Yes               bool `json:"yes"` // non-interactive: skip manual confirm, keep the guard
	ConfirmTimeoutSec int  `json:"confirm_timeout_sec"`
}

type txReq struct {
	TxID string `json:"tx_id"`
}

func (s *Server) mutationEnabled(w http.ResponseWriter) bool {
	if s.proto == nil {
		writeErr(w, http.StatusNotImplemented, errors.New("mutation is disabled (read-only mode)"))
		return false
	}
	return true
}

func (s *Server) buildOptions(req applyReq, physGW netip.Addr) safety.Options {
	anchors := []string{}
	if physGW.IsValid() {
		anchors = append(anchors, physGW.String())
	}
	anchors = append(anchors, "1.1.1.1")
	ct := 15 * time.Second
	if req.ConfirmTimeoutSec > 0 {
		ct = time.Duration(req.ConfirmTimeoutSec) * time.Second
	}
	return safety.Options{
		DryRun:         req.DryRun,
		Interactive:    !req.Yes && !req.DryRun,
		Anchors:        anchors,
		K:              3,
		ProbeInterval:  time.Second,
		ConfirmTimeout: ct,
		GuardWindow:    30 * time.Second,
		Actor:          domain.ActorUI,
		PhysGW:         physGW,
	}
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	if !s.mutationEnabled(w) {
		return
	}
	desired, rules, _, err := s.svc.DesiredManaged(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	plan, diff := s.proto.Plan(r.Context(), desired, rules)
	writeJSON(w, http.StatusOK, map[string]any{"plan": plan, "diff": diff})
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	if !s.mutationEnabled(w) {
		return
	}
	var req applyReq
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)

	desired, rules, physGW, err := s.svc.DesiredManaged(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	// The outcome (committed / failed / refused-with-violations / pending) is
	// encoded in res; the request itself succeeded, so always 200.
	res, _ := s.proto.Apply(r.Context(), desired, rules, s.buildOptions(req, physGW))
	s.BroadcastState(r.Context())
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleConfirm(w http.ResponseWriter, r *http.Request) {
	if !s.mutationEnabled(w) {
		return
	}
	var req txReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	result, err := s.proto.Confirm(req.TxID)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	s.BroadcastState(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"tx_id": req.TxID, "result": result})
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	if !s.mutationEnabled(w) {
		return
	}
	var req txReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	result, err := s.proto.Rollback(req.TxID)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	s.BroadcastState(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"tx_id": req.TxID, "result": result})
}

func (s *Server) handlePanic(w http.ResponseWriter, r *http.Request) {
	if !s.mutationEnabled(w) {
		return
	}
	if err := s.proto.Panic(r.Context(), domain.ActorUI); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.BroadcastState(r.Context())
	writeJSON(w, http.StatusOK, map[string]string{"status": "panicked"})
}

func (s *Server) handleProfileToggle(enable bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.mutationEnabled(w) {
			return
		}
		name := r.PathValue("name")
		if s.store == nil {
			writeErr(w, http.StatusNotImplemented, errors.New("no store"))
			return
		}
		if err := s.store.SetProfileEnabled(name, enable); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeErr(w, http.StatusNotFound, err)
				return
			}
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		// apply=false just stages the desired flag (GUI then previews + applies
		// with commit-confirm). Default true reconciles immediately (CLI quick
		// toggle, non-interactive with the guard kept).
		if r.URL.Query().Get("apply") == "false" {
			s.BroadcastState(r.Context())
			writeJSON(w, http.StatusOK, safety.Result{Status: "staged"})
			return
		}
		// Reconcile to the new enabled set (non-interactive; guard kept).
		desired, rules, physGW, err := s.svc.DesiredManaged(r.Context())
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		res, _ := s.proto.Apply(r.Context(), desired, rules, s.buildOptions(applyReq{Yes: true}, physGW))
		s.BroadcastState(r.Context())
		writeJSON(w, http.StatusOK, res)
	}
}

// ConfigResp is the response to POST /config (declarative apply, spec §10).
type ConfigResp struct {
	Issues []config.Issue `json:"issues,omitempty"`
	Plan   *domain.Plan   `json:"plan,omitempty"`
	Diff   *domain.Diff   `json:"diff,omitempty"`
	Result *safety.Result `json:"result,omitempty"`
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if !s.mutationEnabled(w) {
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	format := config.FormatYAML
	if r.URL.Query().Get("format") == "toml" {
		format = config.FormatTOML
	}
	cfg, vres := config.ParseBytes(data, format, s.svc.Platform())
	resp := ConfigResp{Issues: vres.Issues}
	if vres.HasErrors() {
		writeJSON(w, http.StatusBadRequest, resp) // line-referenced issues
		return
	}
	profiles, lists, _ := cfg.ToDomain()

	if isTrue(r.URL.Query().Get("dry_run")) {
		desired, rules, _, derr := s.svc.DesiredFromProfiles(r.Context(), profiles)
		if derr != nil {
			writeErr(w, http.StatusBadRequest, derr)
			return
		}
		plan, diff := s.proto.Plan(r.Context(), desired, rules)
		resp.Plan, resp.Diff = &plan, &diff
		writeJSON(w, http.StatusOK, resp)
		return
	}

	if s.store != nil {
		for _, p := range profiles {
			_ = s.store.UpsertProfile(p)
		}
		for _, l := range lists {
			_ = s.store.UpsertList(l)
		}
	}
	desired, rules, physGW, derr := s.svc.DesiredManaged(r.Context())
	if derr != nil {
		writeErr(w, http.StatusBadRequest, derr)
		return
	}
	res, _ := s.proto.Apply(r.Context(), desired, rules, s.buildOptions(applyReq{Yes: isTrue(r.URL.Query().Get("yes"))}, physGW))
	resp.Result = &res
	// Apply per-domain resolver selection (split-DNS) alongside the routes.
	if s.splitDNS != nil {
		routes := cfg.SplitDNSRoutes()
		var serr error
		if len(routes) == 0 {
			serr = s.splitDNS.Clear(r.Context())
		} else {
			serr = s.splitDNS.Apply(r.Context(), routes)
		}
		if serr != nil {
			s.log.Warn("split-dns apply failed", "err", serr)
		}
	}
	s.BroadcastState(r.Context())
	writeJSON(w, http.StatusOK, resp)
}

func isTrue(v string) bool { return v == "1" || v == "true" }

func (s *Server) handleListRefresh(w http.ResponseWriter, r *http.Request) {
	if !s.mutationEnabled(w) {
		return
	}
	l, err := s.svc.RefreshList(r.Context(), r.PathValue("name"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, err)
			return
		}
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	s.BroadcastState(r.Context())
	writeJSON(w, http.StatusOK, l)
}

func (s *Server) handleListRefreshAll(w http.ResponseWriter, r *http.Request) {
	if !s.mutationEnabled(w) {
		return
	}
	n, err := s.svc.RefreshAllLists(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	s.BroadcastState(r.Context())
	writeJSON(w, http.StatusOK, map[string]int{"refreshed": n})
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
	var err error
	if req.Enabled {
		err = s.killSwitch.Enable(r.Context(), s.killSwitchConfig(r.Context()))
	} else {
		err = s.killSwitch.Disable(r.Context())
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	on, _ := s.killSwitch.Enabled(r.Context())
	s.BroadcastState(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"kill_switch": on, "backend": s.killSwitch.Backend()})
}

// killSwitchConfig derives the kill switch allow-list from current state: the
// up tunnel interfaces, the physical gateway, and the LAN subnets (so the VPN
// can still reconnect — never a permanent lockout).
func (s *Server) killSwitchConfig(ctx context.Context) killswitch.Config {
	cfg := killswitch.Config{}
	ifaces, _ := s.svc.Interfaces(ctx)
	for _, ifc := range ifaces {
		if !ifc.Up {
			continue
		}
		if ifc.IsVPN {
			cfg.TunnelIfaces = append(cfg.TunnelIfaces, ifc.Name)
			continue
		}
		if ifc.Kind == domain.IfaceKindLoopback {
			continue
		}
		for _, a := range ifc.Addrs {
			if pfx, err := netip.ParsePrefix(a); err == nil && pfx.Addr().Is4() {
				cfg.LANSubnets = append(cfg.LANSubnets, pfx.Masked().String())
			}
		}
	}
	if gw, _, err := s.svc.Provider().DefaultGateway(ctx, domain.FamilyV4); err == nil && gw.IsValid() {
		cfg.Gateway = gw.String()
	}
	return cfg
}

func (s *Server) handleSnapshots(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeJSON(w, http.StatusOK, map[string]any{"snapshots": []domain.Snapshot{}})
		return
	}
	snaps, err := s.store.ListSnapshots()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if snaps == nil {
		snaps = []domain.Snapshot{}
	}
	// Trim heavy route payloads for the list view; details fetched on demand.
	for i := range snaps {
		snaps[i].RoutesV4 = nil
		snaps[i].RoutesV6 = nil
		snaps[i].Rules = nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"snapshots": snaps})
}
