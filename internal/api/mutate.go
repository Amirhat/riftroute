package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Amirhat/riftroute/internal/config"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/killswitch"
	"github.com/Amirhat/riftroute/internal/routing"
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
		prior := s.priorProfiles()
		if err := s.store.SetProfileEnabled(name, enable); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeErr(w, http.StatusNotFound, err)
				return
			}
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		s.notifyProfilesChanged(r.Context())
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
		opts := s.buildOptions(applyReq{Yes: true}, physGW)
		opts.SnapshotProfiles = prior
		res, _ := s.proto.Apply(r.Context(), desired, rules, opts)
		s.BroadcastState(r.Context())
		writeJSON(w, http.StatusOK, res)
	}
}

// priorProfiles returns the CURRENT profile set as a non-nil slice — captured
// by mutating handlers before they touch the store, so the pre-apply snapshot
// records the policy a restore should bring back (not the policy including the
// change being made).
func (s *Server) priorProfiles() []domain.Profile {
	profs, err := s.store.ListProfiles()
	if err != nil {
		return []domain.Profile{}
	}
	if profs == nil {
		profs = []domain.Profile{}
	}
	return profs
}

// routeOpReq is a user-initiated single-route mutation from the routing table:
// delete or replace one EXTERNAL route (one RiftRoute doesn't manage).
type routeOpReq struct {
	Action   string        `json:"action"` // delete | replace
	Route    domain.Route  `json:"route"`
	NewRoute *domain.Route `json:"new_route,omitempty"`
}

// handleRouteOp deletes or edits a single route through the plan-level Apply
// Protocol (WAL + watchdog + commit-confirm; NO ownership records — panic and
// crash-repair must leave user edits of system state alone). Managed routes
// are refused here: they belong to profiles and would be reconciled right
// back — the profile is the thing to edit.
func (s *Server) handleRouteOp(w http.ResponseWriter, r *http.Request) {
	if !s.mutationEnabled(w) {
		return
	}
	var req routeOpReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.Action != "delete" && req.Action != "replace" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("unknown action %q (want delete or replace)", req.Action))
		return
	}
	pfx, err := netip.ParsePrefix(req.Route.DstCIDR)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid destination %q", req.Route.DstCIDR))
		return
	}
	// Canonicalize the destination to its masked form: the kernel operates on
	// the masked prefix, so the guardrail and the managed-route check must see
	// the same thing the provider will (else "128.0.0.0/0" would sidestep both).
	req.Route.DstCIDR = pfx.Masked().String()
	// A route tagged with OUR proto/owner is managed by definition — never
	// route-op it (the profile is the thing to edit).
	if req.Route.Proto == domain.ProtoRiftRoute || req.Route.Owner == domain.OwnerRiftRoute {
		writeErr(w, http.StatusConflict, errors.New(
			"this route is managed by RiftRoute — edit the owning profile instead"))
		return
	}
	// Refuse any route-op whose destination collides with a route we own. The
	// match is by destination+table+family — the granularity the KERNEL delete
	// uses (macOS matches by destination, Linux by destination+proto) — so a
	// perturbed gateway/iface can't sneak a managed route's destination past a
	// full-tuple check and get it deleted out from under its profile.
	if s.store != nil {
		if owned, err := s.store.ListOwned(); err == nil {
			for _, mr := range owned {
				if sameDest(mr.Route, req.Route) {
					writeErr(w, http.StatusConflict, fmt.Errorf(
						"this route is managed by profile %q — edit that profile instead", mr.ProfileID))
					return
				}
			}
		}
	}

	var plan domain.Plan
	platform := s.svc.Platform()
	switch req.Action {
	case "delete":
		plan = routing.DeleteRoutePlan(req.Route, platform)
	case "replace":
		if req.NewRoute == nil {
			writeErr(w, http.StatusBadRequest, errors.New("replace needs new_route"))
			return
		}
		npfx, err := netip.ParsePrefix(req.NewRoute.DstCIDR)
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid new destination %q", req.NewRoute.DstCIDR))
			return
		}
		req.NewRoute.DstCIDR = npfx.Masked().String()
		if req.NewRoute.Gateway != "" {
			if _, err := netip.ParseAddr(req.NewRoute.Gateway); err != nil {
				writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid gateway %q (use an IP address, or leave empty for on-link)", req.NewRoute.Gateway))
				return
			}
		}
		if strings.TrimSpace(req.NewRoute.Iface) == "" {
			writeErr(w, http.StatusBadRequest, errors.New("new route needs an interface"))
			return
		}
		// The edited route keeps the kernel's proto (Linux) and stays main-table.
		req.NewRoute.Proto = req.Route.Proto
		req.NewRoute.Table = req.Route.Table
		req.NewRoute.Family = req.Route.Family
		plan = routing.ReplaceRoutePlan(req.Route, *req.NewRoute, platform)
	}

	gw4, _, _ := s.svc.Provider().DefaultGateway(r.Context(), domain.FamilyV4)
	res, err := s.proto.ApplyPlan(r.Context(), "route-op", plan, s.buildOptions(applyReq{Yes: isTrue(r.URL.Query().Get("yes"))}, gw4))
	if err != nil && !errors.Is(err, safety.ErrGuardrail) {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.BroadcastState(r.Context())
	writeJSON(w, http.StatusOK, ConfigResp{Result: &res})
}

// sameDest reports whether two routes address the same kernel FIB entry —
// destination + table + family, the granularity a kernel delete matches on.
// Gateway/iface are deliberately excluded: the delete would hit the route
// regardless of the next-hop the caller supplied.
func sameDest(a, b domain.Route) bool {
	pa, ea := netip.ParsePrefix(a.DstCIDR)
	pb, eb := netip.ParsePrefix(b.DstCIDR)
	if ea != nil || eb != nil {
		return a.DstCIDR == b.DstCIDR && a.Table == b.Table
	}
	return pa.Masked() == pb.Masked() && a.Table == b.Table
}

// handleProfileSave upserts a single profile assembled by the GUI builder and
// reconciles, sharing the exact strict validation the config-file path uses. With
// ?dry_run=1 it validates + previews the plan WITHOUT persisting; otherwise it
// persists then applies (interactive by default → commit-confirm). Unlike the
// declarative /config path it touches only this one profile, leaving lists and
// split-DNS untouched. Validation errors come back as populated Issues (400).
func (s *Server) handleProfileSave(w http.ResponseWriter, r *http.Request) {
	if !s.mutationEnabled(w) {
		return
	}
	if s.store == nil {
		writeErr(w, http.StatusNotImplemented, errors.New("no store"))
		return
	}
	var p domain.Profile
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	p.Name = strings.TrimSpace(p.Name)

	known := map[string]bool{}
	if ls, err := s.store.ListLists(); err == nil {
		for _, l := range ls {
			known[l.Name] = true
		}
	}
	vres := config.ValidateProfile(p, s.svc.Platform(), known)
	resp := ConfigResp{Issues: vres.Issues}
	if vres.HasErrors() {
		writeJSON(w, http.StatusBadRequest, resp)
		return
	}

	// A brand-new GUI-built profile gets a UNIQUE id (name + timestamp): a plain
	// "gui:<name>" id would collide after a rename — creating a new profile with
	// the freed-up name would silently overwrite the renamed one on upsert.
	if p.ID == "" {
		p.ID = fmt.Sprintf("gui:%s-%x", p.Name, time.Now().UnixNano())
	}
	// Reject a name already owned by a DIFFERENT profile (the store keys by id with
	// a UNIQUE name — surface it as a friendly issue rather than a 500).
	existing, _ := s.store.ListProfiles()
	for _, e := range existing {
		if e.Name == p.Name && e.ID != p.ID {
			resp.Issues = append(resp.Issues, config.Issue{
				Severity: config.SevError, Field: "name",
				Msg: fmt.Sprintf("a different profile already uses the name %q", p.Name),
			})
			writeJSON(w, http.StatusBadRequest, resp)
			return
		}
	}

	if isTrue(r.URL.Query().Get("dry_run")) {
		desired, rules, _, derr := s.svc.DesiredFromProfiles(r.Context(), profilesWith(existing, p))
		if derr != nil {
			writeErr(w, http.StatusBadRequest, derr)
			return
		}
		plan, diff := s.proto.Plan(r.Context(), desired, rules)
		resp.Plan, resp.Diff = &plan, &diff
		writeJSON(w, http.StatusOK, resp)
		return
	}

	prior := s.priorProfiles()
	if err := s.store.UpsertProfile(p); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.notifyProfilesChanged(r.Context())
	desired, rules, physGW, derr := s.svc.DesiredManaged(r.Context())
	if derr != nil {
		// The profile IS saved; only the follow-up reconcile failed (e.g. include
		// mode with no live tunnel). Broadcast so clients show the saved profile,
		// and report the partial success as such — a bare error would read as
		// "the save failed".
		s.BroadcastState(r.Context())
		resp.ApplyError = derr.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}
	opts := s.buildOptions(applyReq{Yes: isTrue(r.URL.Query().Get("yes"))}, physGW)
	opts.SnapshotProfiles = prior
	res, _ := s.proto.Apply(r.Context(), desired, rules, opts)
	resp.Result = &res
	s.BroadcastState(r.Context())
	writeJSON(w, http.StatusOK, resp)
}

// handleProfileDelete removes a profile and reconciles the remaining set. The
// apply is interactive by default so removing a profile's routes is guarded by
// commit-confirm like any other change.
func (s *Server) handleProfileDelete(w http.ResponseWriter, r *http.Request) {
	if !s.mutationEnabled(w) {
		return
	}
	if s.store == nil {
		writeErr(w, http.StatusNotImplemented, errors.New("no store"))
		return
	}
	name := r.PathValue("name")
	prior := s.priorProfiles()
	if err := s.store.DeleteProfile(name); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.notifyProfilesChanged(r.Context())
	desired, rules, physGW, derr := s.svc.DesiredManaged(r.Context())
	if derr != nil {
		// The profile IS deleted; only the follow-up reconcile failed. Broadcast so
		// clients drop the stale profile, and report the partial success as such.
		s.BroadcastState(r.Context())
		writeJSON(w, http.StatusOK, ConfigResp{ApplyError: derr.Error()})
		return
	}
	opts := s.buildOptions(applyReq{Yes: isTrue(r.URL.Query().Get("yes"))}, physGW)
	opts.SnapshotProfiles = prior
	res, _ := s.proto.Apply(r.Context(), desired, rules, opts)
	s.BroadcastState(r.Context())
	writeJSON(w, http.StatusOK, ConfigResp{Result: &res})
}

// profilesWith returns profiles with p substituted in (matched by id or name), or
// appended if new — the desired set for a dry-run preview without persisting.
func profilesWith(profiles []domain.Profile, p domain.Profile) []domain.Profile {
	out := make([]domain.Profile, len(profiles))
	copy(out, profiles)
	for i := range out {
		if out[i].ID == p.ID || out[i].Name == p.Name {
			out[i] = p
			return out
		}
	}
	return append(out, p)
}

// ConfigResp is the response to POST /config (declarative apply, spec §10).
type ConfigResp struct {
	Issues []config.Issue `json:"issues,omitempty"`
	Plan   *domain.Plan   `json:"plan,omitempty"`
	Diff   *domain.Diff   `json:"diff,omitempty"`
	Result *safety.Result `json:"result,omitempty"`
	// ApplyError reports a partial success: the profile change persisted but the
	// follow-up reconcile failed (e.g. include mode with no live tunnel). A bare
	// error here would read as "the save failed" — it didn't.
	ApplyError string `json:"apply_error,omitempty"`
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

	var prior []domain.Profile
	if s.store != nil {
		prior = s.priorProfiles()
		for _, p := range profiles {
			if err := s.store.UpsertProfile(p); err != nil {
				s.log.Warn("config apply: profile not persisted", "profile", p.Name, "err", err)
			}
		}
		for _, l := range lists {
			if err := s.store.UpsertList(l); err != nil {
				s.log.Warn("config apply: list not persisted", "list", l.Name, "err", err)
			}
		}
	}
	s.notifyProfilesChanged(r.Context())
	desired, rules, physGW, derr := s.svc.DesiredManaged(r.Context())
	if derr != nil {
		// The config IS persisted; only the follow-up reconcile failed. Report the
		// partial success as such instead of a bare error.
		s.BroadcastState(r.Context())
		resp.ApplyError = derr.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}
	cfgOpts := s.buildOptions(applyReq{Yes: isTrue(r.URL.Query().Get("yes"))}, physGW)
	cfgOpts.SnapshotProfiles = prior
	res, _ := s.proto.Apply(r.Context(), desired, rules, cfgOpts)
	resp.Result = &res
	// Apply + persist per-domain resolver selection (split-DNS) alongside the
	// routes, so a declarative apply and the Settings editor stay in sync and the
	// selection survives daemon restarts. Only when the file actually HAS a
	// split_dns section — a profiles-only YAML import must not silently wipe a
	// selection the user configured in Settings (absent section = leave alone;
	// explicit empty `split_dns: []` = clear).
	if cfg.Settings.SplitDNS != nil {
		routes := cfg.SplitDNSRoutes()
		if s.store != nil {
			if serr := s.store.SaveSplitDNS(routes); serr != nil {
				s.log.Warn("split-dns persist failed", "err", serr)
			}
		}
		if serr := s.applySplitDNS(r.Context(), routes); serr != nil {
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

// handleListSave upserts a reusable list from the GUI lists manager, with the
// same strict validation the config-file path applies. It only stages: changing a
// list changes desired state, which surfaces as drift for the normal guarded
// Apply — a list edit never mutates the kernel by itself. A remote list is
// fetched immediately (best-effort) so its entries are usable right away.
func (s *Server) handleListSave(w http.ResponseWriter, r *http.Request) {
	if !s.mutationEnabled(w) {
		return
	}
	if s.store == nil {
		writeErr(w, http.StatusNotImplemented, errors.New("no store"))
		return
	}
	var l domain.List
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&l); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	l.Name = strings.TrimSpace(l.Name)
	vres := config.ValidateList(l)
	if vres.HasErrors() {
		writeJSON(w, http.StatusBadRequest, ConfigResp{Issues: vres.Issues})
		return
	}
	// Preserve the fetched cache when editing an existing remote list, unless the
	// source changed (then the old cache no longer describes the source).
	if prev, err := s.store.GetList(l.Name); err == nil && prev.Source == l.Source {
		l.Resolved, l.Checksum, l.LastFetched = prev.Resolved, prev.Checksum, prev.LastFetched
	}
	if err := s.store.UpsertList(l); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if l.Source != "" && l.LastFetched == nil {
		if fetched, err := s.svc.RefreshList(r.Context(), l.Name); err == nil {
			l = fetched
		}
	}
	s.BroadcastState(r.Context())
	writeJSON(w, http.StatusOK, l)
}

// handleListDelete removes a list. Deletion is refused while any profile still
// references it — friendlier than silently breaking those profiles.
func (s *Server) handleListDelete(w http.ResponseWriter, r *http.Request) {
	if !s.mutationEnabled(w) {
		return
	}
	if s.store == nil {
		writeErr(w, http.StatusNotImplemented, errors.New("no store"))
		return
	}
	name := r.PathValue("name")
	if profiles, err := s.store.ListProfiles(); err == nil {
		for _, p := range profiles {
			for _, ref := range p.Lists {
				if ref == name {
					writeErr(w, http.StatusConflict,
						fmt.Errorf("list %q is used by profile %q — remove it from the profile first", name, p.Name))
					return
				}
			}
		}
	}
	if err := s.store.DeleteList(name); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.BroadcastState(r.Context())
	writeJSON(w, http.StatusOK, map[string]string{"deleted": name})
}

// handleSplitDNSGet returns the persisted per-domain resolver routes.
func (s *Server) handleSplitDNSGet(w http.ResponseWriter, _ *http.Request) {
	routes := []domain.SplitDNSRoute{}
	if s.store != nil {
		if rs, err := s.store.LoadSplitDNS(); err == nil && rs != nil {
			routes = rs
		}
	}
	writeJSON(w, http.StatusOK, routes)
}

// handleSplitDNSSet validates, persists, and applies the split-DNS routes (empty
// set clears them). Persisting means they survive daemon restarts — startup
// re-applies whatever is stored.
func (s *Server) handleSplitDNSSet(w http.ResponseWriter, r *http.Request) {
	if !s.mutationEnabled(w) {
		return
	}
	var routes []domain.SplitDNSRoute
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&routes); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var issues []config.Issue
	for _, rt := range routes {
		res := validateSplitDNSRoute(rt)
		issues = append(issues, res...)
	}
	if len(issues) > 0 {
		writeJSON(w, http.StatusBadRequest, ConfigResp{Issues: issues})
		return
	}
	if s.store != nil {
		if err := s.store.SaveSplitDNS(routes); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	}
	if err := s.applySplitDNS(r.Context(), routes); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.BroadcastState(r.Context())
	writeJSON(w, http.StatusOK, routes)
}

func validateSplitDNSRoute(rt domain.SplitDNSRoute) []config.Issue {
	var out []config.Issue
	if !config.IsValidDomain(rt.Domain) {
		out = append(out, config.Issue{Severity: config.SevError, Field: "domain", Msg: fmt.Sprintf("invalid domain %q", rt.Domain)})
	}
	if _, err := netip.ParseAddr(rt.Resolver); err != nil {
		out = append(out, config.Issue{Severity: config.SevError, Field: "resolver", Msg: fmt.Sprintf("resolver must be an IP, got %q", rt.Resolver)})
	}
	return out
}

// applySplitDNS pushes routes through the platform manager (nil manager = no-op;
// empty set clears).
func (s *Server) applySplitDNS(ctx context.Context, routes []domain.SplitDNSRoute) error {
	if s.splitDNS == nil {
		return nil
	}
	if len(routes) == 0 {
		return s.splitDNS.Clear(ctx)
	}
	return s.splitDNS.Apply(ctx, routes)
}

// handleAutoApply toggles automatic reconciliation on network change at runtime
// (the Settings switch). Persisted, so the choice survives daemon restarts.
func (s *Server) handleAutoApply(w http.ResponseWriter, r *http.Request) {
	if s.setAutoApply == nil {
		writeErr(w, http.StatusNotImplemented, errors.New("auto-apply control unavailable"))
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.setAutoApply(req.Enabled)
	if s.store != nil {
		if err := s.store.SetSetting("auto_apply", strconv.FormatBool(req.Enabled)); err != nil {
			s.log.Warn("auto-apply setting not persisted", "err", err)
		}
	}
	s.BroadcastState(r.Context())
	writeJSON(w, http.StatusOK, map[string]bool{"auto_apply": req.Enabled})
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
	// Restorable is derived from the (stripped) profile capture.
	for i := range snaps {
		snaps[i].Restorable = snaps[i].Profiles != nil
		snaps[i].RoutesV4 = nil
		snaps[i].RoutesV6 = nil
		snaps[i].Rules = nil
		snaps[i].Profiles = nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"snapshots": snaps})
}

// handleSnapshotRestore restores the POLICY captured in a snapshot: the profile
// set is put back exactly as it was, then the normal apply path converges
// routes to it (guardrails, WAL, commit-confirm — a restore is as revertible
// as any other change). Snapshots that predate profile capture are refused.
func (s *Server) handleSnapshotRestore(w http.ResponseWriter, r *http.Request) {
	if !s.mutationEnabled(w) {
		return
	}
	if s.store == nil {
		writeErr(w, http.StatusNotImplemented, errors.New("no store"))
		return
	}
	snap, err := s.store.GetSnapshot(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if snap.Profiles == nil {
		writeErr(w, http.StatusBadRequest,
			errors.New("this snapshot predates policy capture and cannot be restored"))
		return
	}

	// Replace the profile set with the snapshot's (exact restore, including
	// removals of profiles created after the snapshot). The pre-restore set is
	// snapshotted in turn, so a restore is itself undoable.
	prior := s.priorProfiles()
	inSnap := map[string]bool{}
	for _, p := range snap.Profiles {
		inSnap[p.ID] = true
	}
	current := prior
	for _, p := range current {
		if !inSnap[p.ID] {
			if derr := s.store.DeleteProfile(p.Name); derr != nil {
				s.log.Warn("restore: could not remove profile", "profile", p.Name, "err", derr)
			}
		}
	}
	for _, p := range snap.Profiles {
		if uerr := s.store.UpsertProfile(p); uerr != nil {
			s.log.Warn("restore: could not restore profile", "profile", p.Name, "err", uerr)
		}
	}
	s.notifyProfilesChanged(r.Context())

	resp := ConfigResp{}
	desired, rules, physGW, derr := s.svc.DesiredManaged(r.Context())
	if derr != nil {
		s.BroadcastState(r.Context())
		resp.ApplyError = derr.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}
	restoreOpts := s.buildOptions(applyReq{Yes: isTrue(r.URL.Query().Get("yes"))}, physGW)
	restoreOpts.SnapshotProfiles = prior
	res, _ := s.proto.Apply(r.Context(), desired, rules, restoreOpts)
	resp.Result = &res
	s.BroadcastState(r.Context())
	writeJSON(w, http.StatusOK, resp)
}
