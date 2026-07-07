package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/wailsapp/wails/v2/pkg/options"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/Amirhat/riftroute/internal/apiclient"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/platform"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/update"
)

// App is the Wails-bound backend. Its exported methods become typed TypeScript
// bindings the React frontend calls; all of them proxy to riftrouted via the
// shared apiclient.
type App struct {
	ctx          context.Context
	client       *apiclient.Client
	cancelEvents context.CancelFunc
}

// NewApp constructs the App.
func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.client = apiclient.New(platform.ClientSocket())

	ec, cancel := context.WithCancel(ctx)
	a.cancelEvents = cancel
	go a.streamEvents(ec)
}

func (a *App) shutdown(_ context.Context) {
	if a.cancelEvents != nil {
		a.cancelEvents()
	}
}

func (a *App) onSecondInstance(_ options.SecondInstanceData) {
	// Focus the existing window instead of launching a second instance.
	wruntime.WindowUnminimise(a.ctx)
	wruntime.WindowShow(a.ctx)
}

// emit re-emits to the React layer as a Wails runtime event.
func (a *App) emit(event string, data ...interface{}) {
	if a.ctx != nil {
		wruntime.EventsEmit(a.ctx, event, data...)
	}
}

// streamEvents holds the daemon's SSE stream and re-emits state/events to React,
// reconnecting with a short backoff if the daemon restarts or isn't up yet.
func (a *App) streamEvents(ctx context.Context) {
	for ctx.Err() == nil {
		err := a.client.Events(ctx, func(ev domain.Event) {
			a.emit("rr:connection", map[string]any{"reachable": true})
			if ev.Type == domain.EventState {
				var st domain.State
				if json.Unmarshal(ev.Data, &st) == nil {
					a.emit("rr:state", st)
				}
				return
			}
			a.emit("rr:event", ev)
		})
		if ctx.Err() != nil {
			return
		}
		_ = err
		a.emit("rr:connection", map[string]any{"reachable": false})
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (a *App) call() (context.Context, context.CancelFunc) {
	return context.WithTimeout(a.ctx, 10*time.Second)
}

// --- bound read methods (typed bindings for React) ---

// GetState returns the aggregate daemon state.
func (a *App) GetState() (domain.State, error) {
	ctx, cancel := a.call()
	defer cancel()
	return a.client.State(ctx)
}

// GetRoutes returns the routing table, optionally filtered by family/owner
// (empty strings mean "all").
func (a *App) GetRoutes(family string, owner string) ([]domain.Route, error) {
	ctx, cancel := a.call()
	defer cancel()
	rs, err := a.client.Routes(ctx, domain.Family(family), domain.Owner(owner))
	if err != nil {
		return nil, err
	}
	if rs == nil {
		rs = []domain.Route{}
	}
	return rs, nil
}

// GetRules returns policy rules — Linux `ip rule` entries or macOS PF
// route-to anchor rules (both families).
func (a *App) GetRules() ([]domain.PolicyRule, error) {
	ctx, cancel := a.call()
	defer cancel()
	rules, err := a.client.Rules(ctx, "")
	if err != nil {
		return nil, err
	}
	if rules == nil {
		rules = []domain.PolicyRule{}
	}
	return rules, nil
}

// GetInterfaces returns the interface list.
func (a *App) GetInterfaces() ([]domain.Iface, error) {
	ctx, cancel := a.call()
	defer cancel()
	ifs, err := a.client.Interfaces(ctx)
	if err != nil {
		return nil, err
	}
	if ifs == nil {
		ifs = []domain.Iface{}
	}
	return ifs, nil
}

// Explain answers "where does traffic to target go?".
func (a *App) Explain(target string) (domain.RouteExplain, error) {
	ctx, cancel := a.call()
	defer cancel()
	return a.client.Explain(ctx, target)
}

// GetProfiles returns stored profiles.
func (a *App) GetProfiles() ([]domain.Profile, error) {
	ctx, cancel := a.call()
	defer cancel()
	ps, err := a.client.Profiles(ctx)
	if err != nil {
		return nil, err
	}
	if ps == nil {
		ps = []domain.Profile{}
	}
	return ps, nil
}

// GetAudit returns recent audit events.
func (a *App) GetAudit() ([]domain.AuditEvent, error) {
	ctx, cancel := a.call()
	defer cancel()
	evs, err := a.client.Audit(ctx, time.Time{})
	if err != nil {
		return nil, err
	}
	if evs == nil {
		evs = []domain.AuditEvent{}
	}
	return evs, nil
}

// --- bound mutation methods (typed bindings for React) ---

// PlanPreview returns the dry-run plan for the current enabled profiles.
func (a *App) PlanPreview() (domain.Plan, error) {
	ctx, cancel := a.call()
	defer cancel()
	plan, _, err := a.client.Plan(ctx)
	return plan, err
}

// Apply reconciles to the enabled profiles. yes = non-interactive (skip manual
// confirm; the guard still runs). confirmTimeoutSec is the daemon's auto-revert
// backstop for interactive applies.
func (a *App) Apply(yes bool, confirmTimeoutSec int) (safety.Result, error) {
	ctx, cancel := a.call()
	defer cancel()
	return a.client.Apply(ctx, apiclient.ApplyOptions{Yes: yes, ConfirmTimeoutSec: confirmTimeoutSec})
}

// Confirm keeps a pending interactive change.
func (a *App) Confirm(txID string) (domain.TxResult, error) {
	ctx, cancel := a.call()
	defer cancel()
	return a.client.Confirm(ctx, txID)
}

// Rollback reverts a pending change immediately.
func (a *App) Rollback(txID string) (domain.TxResult, error) {
	ctx, cancel := a.call()
	defer cancel()
	return a.client.Rollback(ctx, txID)
}

// PanicFlush removes all managed routes and restores baseline (idempotent).
func (a *App) PanicFlush() error {
	ctx, cancel := a.call()
	defer cancel()
	return a.client.Panic(ctx)
}

// SetProfileEnabled stages a profile's desired enabled flag WITHOUT applying, so
// the UI can preview and apply with commit-confirm (spec §8.2). Reconcile is
// driven separately by Apply.
func (a *App) SetProfileEnabled(name string, enable bool) (safety.Result, error) {
	ctx, cancel := a.call()
	defer cancel()
	return a.client.SetProfileEnabled(ctx, name, enable, false)
}

// SaveProfile upserts a profile assembled by the visual builder and reconciles.
// dryRun returns the plan preview without persisting; otherwise it persists then
// applies interactively (the UI runs the commit-confirm on the returned tx).
// Validation errors come back in the result's Issues, not as a thrown error.
func (a *App) SaveProfile(p domain.Profile, dryRun bool) (apiclient.ConfigResult, error) {
	ctx, cancel := a.call()
	defer cancel()
	res, err := a.client.SaveProfile(ctx, p, dryRun, false)
	if err != nil && len(res.Issues) > 0 {
		return res, nil // 400-with-issues is a UI-renderable result, not a transport error
	}
	return res, err
}

// DeleteProfile removes a profile by name and reconciles (interactive apply →
// commit-confirm on the returned tx).
func (a *App) DeleteProfile(name string) (apiclient.ConfigResult, error) {
	ctx, cancel := a.call()
	defer cancel()
	return a.client.DeleteProfile(ctx, name, false)
}

// GetFlows returns live connections correlated to the route that carries them
// (the flow monitor — spec §7.4).
func (a *App) GetFlows() ([]domain.Flow, error) {
	ctx, cancel := a.call()
	defer cancel()
	fl, err := a.client.Flows(ctx)
	if err != nil {
		return nil, err
	}
	if fl == nil {
		fl = []domain.Flow{}
	}
	return fl, nil
}

// GetLists returns the reusable lists with cache metadata.
func (a *App) GetLists() ([]domain.List, error) {
	ctx, cancel := a.call()
	defer cancel()
	ls, err := a.client.Lists(ctx)
	if err != nil {
		return nil, err
	}
	if ls == nil {
		ls = []domain.List{}
	}
	return ls, nil
}

// SaveList upserts a reusable list (visual lists manager). Staging only — the
// change surfaces as drift and routes move on the next guarded Apply.
func (a *App) SaveList(l domain.List) (domain.List, error) {
	ctx, cancel := a.call()
	defer cancel()
	return a.client.SaveList(ctx, l)
}

// DeleteList removes a list (refused while a profile still references it).
func (a *App) DeleteList(name string) error {
	ctx, cancel := a.call()
	defer cancel()
	return a.client.DeleteList(ctx, name)
}

// RefreshList re-fetches a remote list's entries now.
func (a *App) RefreshList(name string) (domain.List, error) {
	ctx, cancel := a.call()
	defer cancel()
	return a.client.RefreshList(ctx, name)
}

// GetSplitDNS returns the persisted per-domain resolver routes.
func (a *App) GetSplitDNS() ([]domain.SplitDNSRoute, error) {
	ctx, cancel := a.call()
	defer cancel()
	routes, err := a.client.SplitDNS(ctx)
	if err != nil {
		return nil, err
	}
	if routes == nil {
		routes = []domain.SplitDNSRoute{}
	}
	return routes, nil
}

// SetSplitDNS validates, persists, and applies the split-DNS selection (empty
// clears it).
func (a *App) SetSplitDNS(routes []domain.SplitDNSRoute) ([]domain.SplitDNSRoute, error) {
	ctx, cancel := a.call()
	defer cancel()
	return a.client.SetSplitDNS(ctx, routes)
}

// CheckUpdate queries GitHub Releases for a newer version (never self-installs;
// spec §7.9 — applying an update stays a documented, verified, manual step).
func (a *App) CheckUpdate() (update.Result, error) {
	ctx, cancel := context.WithTimeout(a.ctx, 15*time.Second)
	defer cancel()
	return update.Check(ctx, nil, "", version)
}

// GetDoctor runs the diagnostics battery.
func (a *App) GetDoctor() (domain.DoctorReport, error) {
	ctx, cancel := a.call()
	defer cancel()
	return a.client.Doctor(ctx)
}

// GetLeaks returns detected IPv6/DNS leaks.
func (a *App) GetLeaks() ([]domain.Leak, error) {
	ctx, cancel := a.call()
	defer cancel()
	lk, err := a.client.Leaks(ctx)
	if err != nil {
		return nil, err
	}
	if lk == nil {
		lk = []domain.Leak{}
	}
	return lk, nil
}

// SetKillSwitch enables/disables the egress kill switch and returns its state.
func (a *App) SetKillSwitch(enabled bool) (bool, error) {
	ctx, cancel := a.call()
	defer cancel()
	return a.client.SetKillSwitch(ctx, enabled)
}

// SetAutoApply toggles reconcile-on-network-change at runtime (persisted).
func (a *App) SetAutoApply(enabled bool) (bool, error) {
	ctx, cancel := a.call()
	defer cancel()
	return a.client.SetAutoApply(ctx, enabled)
}

// GetSnapshots lists snapshot metadata.
func (a *App) GetSnapshots() ([]domain.Snapshot, error) {
	ctx, cancel := a.call()
	defer cancel()
	snaps, err := a.client.Snapshots(ctx)
	if err != nil {
		return nil, err
	}
	if snaps == nil {
		snaps = []domain.Snapshot{}
	}
	return snaps, nil
}

// Reachable reports whether the daemon is currently answering.
func (a *App) Reachable() bool {
	ctx, cancel := a.call()
	defer cancel()
	_, err := a.client.Ping(ctx)
	return err == nil
}

// Version returns the GUI build version.
func (a *App) Version() string { return version }
