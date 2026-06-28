// Package reconcile wires the network monitor to the Apply Protocol: on a
// debounced network event it re-derives desired state and runs the AUTO-APPLY
// path — non-interactive, manual confirm skipped, but the connectivity guard
// always kept (spec §2.2 step 8 / §3.1). Fail-safe: if no gateway/anchor can be
// established the guardrails refuse and existing managed routes are kept.
package reconcile

import (
	"context"
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

// Reconcile derives desired state and runs the auto-apply path once.
func (r *Reconciler) Reconcile(ctx context.Context) (safety.Result, error) {
	if r.enabled != nil && !r.enabled() {
		return safety.Result{}, nil
	}
	desired, rules, physGW, err := r.svc.DesiredManaged(ctx)
	if err != nil {
		// Fail-safe: cannot resolve gateway/desired → keep existing routes.
		r.log.Warn("auto-apply skipped: cannot derive desired state", "err", err)
		return safety.Result{}, err
	}
	anchors := []string{}
	if physGW.IsValid() {
		anchors = append(anchors, physGW.String())
	}
	anchors = append(anchors, "1.1.1.1")

	res, aerr := r.proto.Apply(ctx, desired, rules, safety.Options{
		Interactive:   false, // auto-apply: skip manual confirm, keep the guard
		Anchors:       anchors,
		K:             3,
		ProbeInterval: time.Second,
		GuardWindow:   30 * time.Second,
		Actor:         domain.ActorDaemon,
		PhysGW:        physGW,
	})
	if r.onReconcile != nil {
		r.onReconcile(res, aerr)
	}
	return res, aerr
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
