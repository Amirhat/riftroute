// Package reconcile wires the network monitor to the Apply Protocol: on a
// debounced network event it re-derives desired state and runs the AUTO-APPLY
// path — non-interactive, manual confirm skipped, but the connectivity guard
// always kept (spec §2.2 step 8 / §3.1). Fail-safe: if no gateway/anchor can be
// established the guardrails refuse and existing managed routes are kept.
package reconcile

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/netmon"
	"github.com/Amirhat/riftroute/internal/safety"
)

// Reconciler runs the auto-apply path in response to network events.
type Reconciler struct {
	svc      *core.Service
	proto    *safety.Protocol
	log      *slog.Logger
	debounce time.Duration
	enabled  func() bool

	// onReconcile is an optional test hook fired after each reconcile.
	onReconcile func(safety.Result, error)
}

// New builds a Reconciler. enabled gates auto-apply (nil = always on).
func New(svc *core.Service, proto *safety.Protocol, log *slog.Logger, debounce time.Duration, enabled func() bool) *Reconciler {
	if log == nil {
		log = slog.Default()
	}
	return &Reconciler{svc: svc, proto: proto, log: log, debounce: debounce, enabled: enabled}
}

// SetTestHook installs a callback fired after each reconcile (tests only).
func (r *Reconciler) SetTestHook(fn func(safety.Result, error)) { r.onReconcile = fn }

// Reconcile derives desired state and runs the auto-apply path once. Desired
// state is derived under the apply lock, so a tunnel transition landing
// meanwhile is never undone by a set computed before it.
func (r *Reconciler) Reconcile(ctx context.Context) (safety.Result, error) {
	if r.enabled != nil && !r.enabled() {
		return safety.Result{}, nil
	}
	var buildErr error
	res, err := r.proto.ApplyBuilt(ctx, func([]domain.ManagedRoute) ([]domain.ManagedRoute, []domain.ManagedRule, error) {
		desired, rules, _, err := r.svc.DesiredManaged(ctx)
		buildErr = err
		return desired, rules, err
	}, r.options(ctx))
	if buildErr != nil {
		// Fail-safe: cannot resolve gateway/desired → keep existing routes.
		r.log.Warn("auto-apply skipped: cannot derive desired state", "err", buildErr)
		return safety.Result{}, buildErr
	}
	if r.onReconcile != nil {
		r.onReconcile(res, err)
	}
	return res, err
}

// ApplyTunnels installs the managed tunnels' current routes and leaves every
// other managed route as it is. It is NOT gated by auto-apply — connecting or
// disconnecting a tunnel is the user's explicit action — but it runs the same
// guarded, non-interactive path, deriving the set under the apply lock from
// what RiftRoute owns at that moment.
func (r *Reconciler) ApplyTunnels(ctx context.Context) error {
	res, err := r.proto.ApplyBuilt(ctx, func(owned []domain.ManagedRoute) ([]domain.ManagedRoute, []domain.ManagedRule, error) {
		return r.svc.DesiredTunnelsOnly(ctx, owned)
	}, r.options(ctx))
	if err == nil && res.Status == domain.TxFailed {
		err = errors.New(res.Error)
	}
	return err
}

// options are a guarded, non-interactive apply's.
func (r *Reconciler) options(ctx context.Context) safety.Options {
	physGW := r.svc.PhysicalGateway(ctx)
	return safety.Options{
		Interactive:   false, // auto-apply: skip manual confirm, keep the guard
		Anchors:       safety.DefaultAnchors(physGW),
		K:             3,
		ProbeInterval: time.Second,
		GuardWindow:   30 * time.Second,
		Actor:         domain.ActorDaemon,
		PhysGW:        physGW,
	}
}

// Run consumes network events, debounces them, and reconciles. It blocks until
// ctx is canceled.
func (r *Reconciler) Run(ctx context.Context, events <-chan netmon.Event) {
	var timerC <-chan time.Time
	var timer *time.Timer

	do := func() {
		if _, err := r.Reconcile(ctx); err != nil {
			r.log.Warn("auto-apply reconcile failed", "err", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			r.log.Debug("network event", "type", ev.Type, "iface", ev.Iface)
			if r.debounce <= 0 {
				do()
				continue
			}
			if timer != nil {
				timer.Stop()
			}
			timer = time.NewTimer(r.debounce)
			timerC = timer.C
		case <-timerC:
			timerC = nil
			do()
		}
	}
}
