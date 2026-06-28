package main

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/wailsapp/wails/v2/pkg/options"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/Amirhat/riftroute/internal/apiclient"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/platform"
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
	sock := os.Getenv("RIFTROUTE_SOCKET")
	if sock == "" {
		sock = platform.DefaultPaths().Socket
	}
	a.client = apiclient.New(sock)

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

// Reachable reports whether the daemon is currently answering.
func (a *App) Reachable() bool {
	ctx, cancel := a.call()
	defer cancel()
	_, err := a.client.Ping(ctx)
	return err == nil
}

// Version returns the GUI build version.
func (a *App) Version() string { return version }
