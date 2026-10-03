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

	// liveEvery: how often Run looks for routes RiftRoute installed that
	// another program removed (0: never).
	liveEvery time.Duration

	// onReconcile is an optional test hook fired after each reconcile.
	onReconcile func(safety.Result, error)
}

// LiveCheckInterval is how often, with auto-apply on, the reconciler looks
// for routes RiftRoute installed that another program removed — a VPN client
// tidying the table changes no default route or interface, so no network
// event comes. Finding some, it reconciles, which puts them back
// (routing.VerifyRoutes); one that keeps being removed is held instead
// (safety's live repair).
const LiveCheckInterval = 30 * time.Second

// New builds a Reconciler. enabled gates auto-apply (nil = always on).
func New(svc *core.Service, proto *safety.Protocol, log *slog.Logger, debounce time.Duration, enabled func() bool) *Reconciler {
	if log == nil {
		log = slog.Default()
	}
	return &Reconciler{svc: svc, proto: proto, log: log, debounce: debounce, enabled: enabled, liveEvery: LiveCheckInterval}
}

// SetLiveCheck sets how often Run looks for removed routes (0: never).
func (r *Reconciler) SetLiveCheck(every time.Duration) { r.liveEvery = every }

// SetTestHook installs a callback fired after each reconcile (tests only).
func (r *Reconciler) SetTestHook(fn func(safety.Result, error)) { r.onReconcile = fn }

// Reconcile derives desired state and runs the auto-apply path once. Desired
// state is derived under the apply lock, so a tunnel transition landing
// meanwhile is never undone by a set computed before it.
//
// With auto-apply off, only the tunnels RiftRoute runs follow the network:
// they are the user's explicit choice, and their server pins must move with
// the physical gateway or their connections ride the wrong path.
func (r *Reconciler) Reconcile(ctx context.Context) (safety.Result, error) {
	if r.enabled != nil && !r.enabled() {
		if !r.svc.TunnelsActive(ctx) {
			return safety.Result{}, nil
		}
		res, err := r.applyTunnels(ctx)
		if r.onReconcile != nil {
			r.onReconcile(res, err)
		}
		return res, err
	}
	var buildErr error
	res, err := r.proto.ApplyBuilt(ctx, func(ctx context.Context, _ []domain.ManagedRoute, o *safety.Options) ([]domain.ManagedRoute, []domain.ManagedRule, error) {
		desired, rules, physGW, record, err := r.svc.DesiredForApply(ctx)
		buildErr = err
		o.UseGateway(physGW)
		o.OnCommit = record
		return desired, rules, err
	}, options())
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
	res, err := r.applyTunnels(ctx)
	if err == nil && res.Status == domain.TxFailed {
		err = errors.New(res.Error)
	}
	return err
}

// applyTunnels is ApplyTunnels' apply. The guardrails vet what it changes:
// the other owned routes it carries over untouched may be stale (auto-apply
// off after a network move) and must not stop a tunnel installing or
// withdrawing its own.
//
// It commits without a guard (safety.Options.Unguarded): what it changes
// can't cut the gateway, a resolver or an anchor — a tunnel route holding one
// is left out (routing.TunnelRouteBlock) — and a watchdog rollback would do
// harm: re-add a withdrawn on-link route into an interface that's gone, or
// withdraw a live tunnel's routes with nothing to put them back.
func (r *Reconciler) applyTunnels(ctx context.Context) (safety.Result, error) {
	opts := options()
	opts.VetChangesOnly = true
	opts.Unguarded = true
	opts.BuiltOnRecord = true // it puts back what the last full apply made yield
	opts.Lendable = true      // it runs under a restarting updater's lock (LendQuiesce)
	return r.proto.ApplyBuilt(ctx, func(ctx context.Context, owned []domain.ManagedRoute, o *safety.Options) ([]domain.ManagedRoute, []domain.ManagedRule, error) {
		desired, rules, physGW, record, err := r.svc.TunnelsForApply(ctx, owned)
		o.UseGateway(physGW)
		o.OnCommit = record
		return desired, rules, err
	}, opts)
}

// options are a guarded, non-interactive apply's. The physical gateway and
// the anchors are the build's to set (safety.Options.UseGateway), from the
// reads the desired set is built from.
func options() safety.Options {
	return safety.Options{
		Interactive:   false, // auto-apply: skip manual confirm, keep the guard
		K:             3,
		ProbeInterval: time.Second,
		GuardWindow:   30 * time.Second,
		Actor:         domain.ActorDaemon,
	}
}

// Run consumes network events, debounces them, and reconciles. It blocks until
// ctx is canceled.
func (r *Reconciler) Run(ctx context.Context, events <-chan netmon.Event) {
	var timerC <-chan time.Time
	var timer *time.Timer
	var liveC <-chan time.Time
	if r.liveEvery > 0 {
		t := time.NewTicker(r.liveEvery)
		defer t.Stop()
		liveC = t.C
	}

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
		case <-liveC:
			if r.enabled != nil && !r.enabled() {
				continue // with auto-apply off, drift shows them; an apply puts them back
			}
			if n := r.svc.LiveMissing(ctx); n > 0 {
				r.log.Info("routes RiftRoute installed are gone from the kernel; putting them back", "count", n)
				do()
			}
		}
	}
}
