package api

import (
	"context"
	"net/http"
	"time"

	"github.com/Amirhat/riftroute/internal/bugreport"
	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/platform"
	"github.com/Amirhat/riftroute/internal/store"
)

// handleBugReport renders the redacted diagnostics report (never uploaded —
// the client shows it to the user, who decides where it goes).
func (s *Server) handleBugReport(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, bugreport.Render(gatherBugReport(ctx, s.svc, s.store)))
}

// gatherBugReport collects a report's input from the running daemon. Every
// source is best-effort: a report is most needed exactly when something is
// broken, so a failing read leaves its section empty instead of failing.
func gatherBugReport(ctx context.Context, svc *core.Service, st *store.Store) bugreport.Input {
	in := bugreport.Input{Now: time.Now(), OS: platform.OSDescription(), Hosts: platform.HostNames()}
	if s, err := svc.State(ctx); err == nil {
		in.State = s
	} else {
		in.State.Health = svc.Health()
		in.State.Health.Reason = err.Error()
	}
	if st != nil {
		in.Profiles, _ = st.ListProfiles()
		in.SplitDNS, _ = st.LoadSplitDNS()
		in.Audit, _ = st.ListAudit(time.Time{}, bugreport.MaxAudit)
		pend, err := st.ListPendingTx()
		in.Pending = len(pend)
		if err != nil {
			in.PendingErr = err.Error()
		}
	}
	in.Lists, _ = svc.Lists()
	in.Routes, _ = svc.Routes(ctx, "", "")
	in.Doctor = svc.Doctor(ctx)
	in.Log, in.LogSource = platform.DaemonLogTail(bugreport.MaxLogLines)
	in.Users = bugreport.LocalUserNames(ctx)
	return in
}
