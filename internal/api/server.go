// Package api is the daemon's local control plane: HTTP/JSON over a Unix domain
// socket plus an SSE event stream, guarded by OS peer-credential authz (spec
// §11/§12). There is no TCP and no network binding. The desktop app's Go side
// and the CLI both reach the daemon through this surface via the shared
// apiclient; the React layer never speaks HTTP/SSE directly.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/killswitch"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/splitdns"
	"github.com/Amirhat/riftroute/internal/store"
	"github.com/Amirhat/riftroute/internal/sysinfo"
)

// Server exposes the daemon's core over a UDS.
type Server struct {
	svc      *core.Service
	store    *store.Store
	proto    *safety.Protocol
	hub      *Hub
	allowUID uint32
	version  string
	log      *slog.Logger
	mux      *http.ServeMux

	// debugVPN, if set (fake provider only), toggles the simulated VPN so the
	// auto-apply path can be demonstrated against a running daemon. nil in prod.
	debugVPN func(up bool)

	// killSwitch fences egress to the tunnel when enabled (nil disables the API).
	killSwitch killswitch.Manager
	// splitDNS applies per-domain resolver selection (nil = no-op).
	splitDNS splitdns.Manager
	// setAutoApply flips the daemon's auto-apply gate at runtime (nil disables
	// the endpoint; the daemon wires it to an atomic the reconciler reads).
	setAutoApply func(on bool)
	// onProfilesChanged fires after any mutation that alters the profile set, so
	// the daemon can sync profile-derived side state (the Linux per-app cgroup
	// marker). nil = no-op.
	onProfilesChanged func(context.Context)
}

// SetDebugVPN installs a fake-VPN toggle (daemon wires this only for -provider
// fake). It enables live auto-apply demos without touching real networking.
func (s *Server) SetDebugVPN(fn func(up bool)) { s.debugVPN = fn }

// SetKillSwitch installs the kill-switch manager (daemon wiring).
func (s *Server) SetKillSwitch(m killswitch.Manager) { s.killSwitch = m }

// SetSplitDNS installs the split-DNS manager (daemon wiring).
func (s *Server) SetSplitDNS(m splitdns.Manager) { s.splitDNS = m }

// SetAutoApplyControl installs the runtime auto-apply setter (daemon wiring).
func (s *Server) SetAutoApplyControl(fn func(on bool)) { s.setAutoApply = fn }

// SetOnProfilesChanged installs the post-profile-mutation hook (daemon wiring).
func (s *Server) SetOnProfilesChanged(fn func(context.Context)) { s.onProfilesChanged = fn }

// notifyProfilesChanged fires the profile-mutation hook, if wired.
func (s *Server) notifyProfilesChanged(ctx context.Context) {
	if s.onProfilesChanged != nil {
		s.onProfilesChanged(ctx)
	}
}

// NewServer builds the API server. allowUID is the uid permitted to call
// mutating endpoints (root is always permitted); reads are open to any local
// peer that can reach the 0600 socket. proto may be nil to disable mutation
// (read-only mode).
func NewServer(svc *core.Service, st *store.Store, proto *safety.Protocol, allowUID uint32, version string, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		svc: svc, store: st, proto: proto, hub: NewHub(), allowUID: allowUID, version: version, log: logger,
	}
	s.routes()
	return s
}

// Hub returns the SSE broadcast hub so the daemon can push events.
func (s *Server) Hub() *Hub { return s.hub }

// Handler returns the bare HTTP handler (for tests via httptest).
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux = http.NewServeMux()
	// Read-only endpoints (M0/M1). Open to any authenticated local peer.
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /state", s.handleState)
	s.mux.HandleFunc("GET /routes", s.handleRoutes)
	s.mux.HandleFunc("GET /rules", s.handleRules)
	s.mux.HandleFunc("GET /interfaces", s.handleInterfaces)
	s.mux.HandleFunc("GET /dns", s.handleDNS)
	s.mux.HandleFunc("POST /route/explain", s.handleExplain)
	s.mux.HandleFunc("GET /diff", s.handleDiff)
	s.mux.HandleFunc("GET /conflicts", s.handleConflicts)
	s.mux.HandleFunc("GET /doctor", s.handleDoctor)
	s.mux.HandleFunc("GET /leaks", s.handleLeaks)
	s.mux.HandleFunc("GET /flows", s.handleFlows)
	s.mux.HandleFunc("GET /profiles", s.handleProfiles)
	s.mux.HandleFunc("GET /lists", s.handleLists)
	s.mux.HandleFunc("GET /audit", s.handleAudit)
	s.mux.HandleFunc("GET /snapshots", s.handleSnapshots)
	s.mux.HandleFunc("GET /events", s.handleEvents)
	// Local catalogs for the GUI's per-app pickers (users / cgroup units).
	s.mux.HandleFunc("GET /system/users", s.handleSystemUsers)
	s.mux.HandleFunc("GET /system/apps", s.handleSystemApps)

	// Mutating endpoints — peer-credential gated (spec §12). /plan is a dry-run
	// preview and does not mutate, but lives with its siblings for clarity.
	s.mux.HandleFunc("POST /plan", s.handlePlan)
	s.mux.HandleFunc("POST /apply", s.requireWrite(s.handleApply))
	s.mux.HandleFunc("POST /confirm", s.requireWrite(s.handleConfirm))
	s.mux.HandleFunc("POST /rollback", s.requireWrite(s.handleRollback))
	s.mux.HandleFunc("POST /panic", s.requireWrite(s.handlePanic))
	s.mux.HandleFunc("POST /config", s.requireWrite(s.handleConfig))
	s.mux.HandleFunc("POST /killswitch", s.requireWrite(s.handleKillSwitch))
	s.mux.HandleFunc("POST /lists/refresh", s.requireWrite(s.handleListRefreshAll))
	s.mux.HandleFunc("POST /lists/{name}/refresh", s.requireWrite(s.handleListRefresh))
	s.mux.HandleFunc("POST /profiles/{name}/enable", s.requireWrite(s.handleProfileToggle(true)))
	s.mux.HandleFunc("POST /profiles/{name}/disable", s.requireWrite(s.handleProfileToggle(false)))
	// Interactive GUI builder: upsert one profile (validate → apply) / delete one.
	s.mux.HandleFunc("POST /profiles", s.requireWrite(s.handleProfileSave))
	s.mux.HandleFunc("DELETE /profiles/{name}", s.requireWrite(s.handleProfileDelete))
	// GUI lists manager: upsert/delete a reusable list (staging only; drift-driven apply).
	s.mux.HandleFunc("POST /lists", s.requireWrite(s.handleListSave))
	s.mux.HandleFunc("DELETE /lists/{name}", s.requireWrite(s.handleListDelete))
	// Split-DNS: persisted per-domain resolver selection, editable from Settings.
	s.mux.HandleFunc("GET /splitdns", s.handleSplitDNSGet)
	s.mux.HandleFunc("PUT /splitdns", s.requireWrite(s.handleSplitDNSSet))
	// Snapshot restore: put the captured profile set back, then reconcile.
	s.mux.HandleFunc("POST /snapshots/{id}/restore", s.requireWrite(s.handleSnapshotRestore))
	// Auto-apply: runtime toggle for reconcile-on-network-change (Settings).
	s.mux.HandleFunc("PUT /autoapply", s.requireWrite(s.handleAutoApply))
	// Fake-only: toggle the simulated VPN to exercise auto-apply (no-op in prod).
	s.mux.HandleFunc("POST /debug/vpn", s.requireWrite(s.handleDebugVPN))
}

func (s *Server) handleDebugVPN(w http.ResponseWriter, r *http.Request) {
	if s.debugVPN == nil {
		writeErr(w, http.StatusNotImplemented, errors.New("debug endpoint not enabled (fake provider only)"))
		return
	}
	up := r.URL.Query().Get("up") != "false"
	s.debugVPN(up)
	writeJSON(w, http.StatusOK, map[string]any{"vpn_up": up})
}

// Serve runs the HTTP server over ln (a UDS listener) until ctx is canceled. It
// wraps ln so every accepted connection carries its peer's credentials.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if cc, ok := c.(*credConn); ok {
				return context.WithValue(ctx, peerKey{}, peerInfo{uid: cc.uid, gid: cc.gid, err: cc.credErr})
			}
			return ctx
		},
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	err := srv.Serve(credListener{Listener: ln})
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// --- handlers ---

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.version})
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	st, err := s.svc.State(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	family := domain.Family(r.URL.Query().Get("family"))
	owner := domain.Owner(r.URL.Query().Get("owner"))
	routes, err := s.svc.Routes(r.Context(), family, owner)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"routes": routes, "count": len(routes)})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	family := domain.Family(r.URL.Query().Get("family"))
	rules, err := s.svc.Rules(r.Context(), family)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules, "count": len(rules)})
}

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := s.svc.Interfaces(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"interfaces": ifaces})
}

func (s *Server) handleDNS(w http.ResponseWriter, r *http.Request) {
	dns, err := s.svc.DNS(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, dns)
}

func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	res, err := s.svc.Explain(r.Context(), body.Target)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	// With the engine available, diff = desired (from enabled profiles) vs actual
	// managed. Without it (read-only mode) fall back to the empty-desired diff.
	if s.proto != nil {
		desired, rules, _, err := s.svc.DesiredManaged(r.Context())
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		_, diff := s.proto.Plan(r.Context(), desired, rules)
		writeJSON(w, http.StatusOK, diff)
		return
	}
	d, err := s.svc.Diff(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleConflicts(w http.ResponseWriter, r *http.Request) {
	if s.proto == nil {
		writeJSON(w, http.StatusOK, map[string]any{"conflicts": []domain.Conflict{}})
		return
	}
	cs, err := s.svc.Conflicts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if cs == nil {
		cs = []domain.Conflict{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"conflicts": cs})
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeJSON(w, http.StatusOK, map[string]any{"profiles": []domain.Profile{}})
		return
	}
	profs, err := s.store.ListProfiles()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if profs == nil {
		profs = []domain.Profile{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": profs})
}

func (s *Server) handleDoctor(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Doctor(r.Context()))
}

func (s *Server) handleSystemUsers(w http.ResponseWriter, r *http.Request) {
	users, err := sysinfo.Users(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if users == nil {
		users = []sysinfo.User{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *Server) handleSystemApps(w http.ResponseWriter, r *http.Request) {
	apps, err := sysinfo.Apps(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if apps == nil {
		apps = []sysinfo.App{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": apps})
}

func (s *Server) handleLeaks(w http.ResponseWriter, r *http.Request) {
	lk := s.svc.Leaks(r.Context())
	if lk == nil {
		lk = []domain.Leak{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"leaks": lk})
}

func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	flows, err := s.svc.Flows(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if flows == nil {
		flows = []domain.Flow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"flows": flows})
}

func (s *Server) handleLists(w http.ResponseWriter, r *http.Request) {
	ls, err := s.svc.Lists()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if ls == nil {
		ls = []domain.List{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"lists": ls})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	var since time.Time
	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			since = t
		}
	}
	if s.store == nil {
		writeJSON(w, http.StatusOK, map[string]any{"events": []domain.AuditEvent{}})
		return
	}
	evs, err := s.store.ListAudit(since, 200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if evs == nil {
		evs = []domain.AuditEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": evs})
}

// --- json helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
