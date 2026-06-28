package safety

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider"
	"github.com/Amirhat/riftroute/internal/routing"
)

// Errors returned by the Apply Protocol. Callers (CLI/API) map these to stable
// exit codes / status codes.
var (
	ErrGuardrail       = errors.New("change refused by a guardrail")
	ErrApplyInProgress = errors.New("another apply is pending; try again")
	ErrNoSuchTx        = errors.New("no such transaction")
)

// Store is the slice of persistence the Apply Protocol needs (satisfied by
// *store.Store). Keeping it an interface keeps safety decoupled and testable.
type Store interface {
	AddOwned(domain.ManagedRoute) error
	DelOwned(domain.ManagedRoute) error
	ListOwned() ([]domain.ManagedRoute, error)
	ClearOwned() error
	SaveSnapshot(domain.Snapshot) error
	AppendAudit(domain.AuditEvent) (int64, error)
}

// Options configure a single apply (spec §2.2/§10 connectivity_guard).
type Options struct {
	DryRun         bool
	Interactive    bool          // true → commit-confirm; false → auto-commit after guard window
	Anchors        []string      // connectivity anchors (already resolved, e.g. gateway IP)
	K              int           // consecutive failed probes that fire rollback
	ProbeInterval  time.Duration // watchdog probe cadence
	ConfirmTimeout time.Duration // interactive auto-revert window
	GuardWindow    time.Duration // non-interactive guard window
	Actor          domain.Actor
	PhysGW         netip.Addr // physical gateway, for guardrails
}

func (o Options) window() time.Duration {
	if o.Interactive {
		if o.ConfirmTimeout <= 0 {
			return 15 * time.Second
		}
		return o.ConfirmTimeout
	}
	if o.GuardWindow <= 0 {
		return 30 * time.Second
	}
	return o.GuardWindow
}

// Result is the outcome of Plan/Apply.
type Result struct {
	TxID         string          `json:"tx_id,omitempty"`
	Plan         domain.Plan     `json:"plan"`
	Diff         domain.Diff     `json:"diff"`
	Violations   []Violation     `json:"violations,omitempty"`
	Status       domain.TxResult `json:"status"`
	NeedsConfirm bool            `json:"needs_confirm"`
	Error        string          `json:"error,omitempty"`
}

type decision int

const (
	decCommit decision = iota
	decRollback
)

type pendingTx struct {
	id          string
	plan        domain.Plan
	interactive bool
	decided     chan decision
	cancel      context.CancelFunc
	done        chan struct{}
	result      domain.TxResult
}

func (pt *pendingTx) decide(d decision) {
	select {
	case pt.decided <- d:
	default: // already decided; ignore
	}
}

// Protocol runs the Apply Protocol (spec §2.2). All mutating applies are
// serialized; only one transaction may be unresolved at a time.
type Protocol struct {
	prov      provider.RouteProvider
	store     Store
	clock     Clock
	newProber func() Prober
	platform  string
	log       *slog.Logger

	applyMu  sync.Mutex
	txmu     sync.Mutex
	pending  map[string]*pendingTx
	resolved map[string]domain.TxResult
	idseq    int
}

// NewProtocol builds an Apply Protocol. newProber may be nil (defaults to a TCP
// dial prober). clock may be nil (defaults to the real clock).
func NewProtocol(prov provider.RouteProvider, st Store, clock Clock, newProber func() Prober, platform string, log *slog.Logger) *Protocol {
	if clock == nil {
		clock = RealClock{}
	}
	if newProber == nil {
		newProber = func() Prober { return DialProber{} }
	}
	if log == nil {
		log = slog.Default()
	}
	return &Protocol{
		prov: prov, store: st, clock: clock, newProber: newProber, platform: platform, log: log,
		pending: map[string]*pendingTx{}, resolved: map[string]domain.TxResult{},
	}
}

// Plan builds the reconcile plan + diff for desired state without applying — the
// dry-run preview (spec §2.2 step 4).
func (p *Protocol) Plan(ctx context.Context, desiredRoutes []domain.ManagedRoute, desiredRules []domain.ManagedRule) (domain.Plan, domain.Diff) {
	plan := routing.Reconcile(desiredRoutes, p.actualManaged(ctx), desiredRules, p.actualManagedRules(ctx), p.platform)
	return plan, diffFromPlan(plan)
}

// Apply runs the full Apply Protocol. For DryRun it returns the preview. On
// success it executes atomically, arms the watchdog + commit-confirm, and
// returns a pending transaction (resolved later via Confirm/timeout/watchdog).
func (p *Protocol) Apply(ctx context.Context, desired []domain.ManagedRoute, desiredRules []domain.ManagedRule, opts Options) (Result, error) {
	p.applyMu.Lock()
	defer p.applyMu.Unlock()

	plan := routing.Reconcile(desired, p.actualManaged(ctx), desiredRules, p.actualManagedRules(ctx), p.platform)
	diff := diffFromPlan(plan)

	if opts.DryRun {
		return Result{Plan: plan, Diff: diff, Status: domain.TxPending}, nil
	}

	// Guardrails (§2.4) — refuse before touching anything.
	if vs := CheckGuardrails(ctx, p.prov, desired, opts.PhysGW); len(vs) > 0 {
		p.audit(opts.Actor, "apply", "refused", violationSummary(vs), &plan, false)
		return Result{Plan: plan, Diff: diff, Violations: vs, Status: domain.TxFailed, Error: ErrGuardrail.Error()}, ErrGuardrail
	}

	if len(plan.Ops) == 0 {
		return Result{Plan: plan, Diff: diff, Status: domain.TxCommitted}, nil
	}

	// Serialize applies (spec §11). An interactive change awaiting confirmation
	// blocks new applies; a non-interactive change is just guarding in the
	// background, so a new apply supersedes it (commit it, stop its guard).
	p.txmu.Lock()
	var supersede []*pendingTx
	for _, pt := range p.pending {
		if pt.interactive {
			p.txmu.Unlock()
			return Result{Plan: plan, Diff: diff, Status: domain.TxFailed, Error: ErrApplyInProgress.Error()}, ErrApplyInProgress
		}
		supersede = append(supersede, pt)
	}
	p.txmu.Unlock()
	for _, pt := range supersede {
		pt.decide(decCommit)
		<-pt.done
	}

	// Snapshot (restore point of last resort behind the inverse).
	if p.store != nil {
		if snap, err := Capture(ctx, p.prov, p.nextSnapID(), "pre-apply", func() domain.Snapshot {
			return domain.Snapshot{CreatedAt: p.clock.Now()}
		}); err == nil {
			_ = p.store.SaveSnapshot(snap)
		}
	}

	// EXECUTE atomically; on error the executor has already rolled back.
	exec := NewExecutor(p.prov)
	if err := exec.Apply(ctx, plan); err != nil {
		p.audit(opts.Actor, "apply", string(domain.TxFailed), err.Error(), &plan, true)
		return Result{Plan: plan, Diff: diff, Status: domain.TxFailed, Error: err.Error()}, nil
	}

	// Record ownership for the applied delta and audit the applied change.
	p.applyOwnership(plan, false)
	p.audit(opts.Actor, "apply", "applied", "", &plan, false)

	// ARM watchdog + commit-confirm and resolve in the background.
	txID := p.nextTxID()
	ctxTx, cancel := context.WithCancel(context.Background())
	pt := &pendingTx{id: txID, plan: plan, interactive: opts.Interactive, decided: make(chan decision, 4), cancel: cancel, done: make(chan struct{})}
	p.register(pt)

	prober := p.newProber()
	guardFirst := p.clock.After(opts.ProbeInterval) // registered synchronously (fake-clock safe)
	decisionTimer := p.clock.After(opts.window())
	wd := NewWatchdog(p.clock, prober, opts.Anchors, opts.K, opts.ProbeInterval, func() { pt.decide(decRollback) })
	go wd.Run(ctxTx, guardFirst)
	go func() {
		select {
		case <-ctxTx.Done():
		case <-decisionTimer:
			if opts.Interactive {
				pt.decide(decRollback) // missed confirm → auto-revert
			} else {
				pt.decide(decCommit) // guard window elapsed cleanly → commit
			}
		}
	}()
	go p.resolve(pt, opts.Actor)

	return Result{TxID: txID, Plan: plan, Diff: diff, Status: domain.TxPending, NeedsConfirm: opts.Interactive}, nil
}

func (p *Protocol) resolve(pt *pendingTx, actor domain.Actor) {
	d := <-pt.decided
	pt.cancel() // stop watchdog + decision timer
	if d == decCommit {
		pt.result = domain.TxCommitted
		p.audit(actor, "confirm", "committed", "", nil, false)
	} else {
		exec := NewExecutor(p.prov)
		_ = exec.RunOps(context.Background(), pt.plan.Inverse)
		p.applyOwnership(pt.plan, true)
		pt.result = domain.TxRolledBack
		p.audit(actor, "rollback", "rolled_back", "watchdog or missed confirm", nil, true)
	}
	p.txmu.Lock()
	p.resolved[pt.id] = pt.result
	delete(p.pending, pt.id)
	p.txmu.Unlock()
	close(pt.done)
}

// Confirm keeps a pending interactive change (cancels the auto-revert).
func (p *Protocol) Confirm(txID string) (domain.TxResult, error) {
	pt := p.lookup(txID)
	if pt == nil {
		if res, ok := p.resolvedResult(txID); ok {
			return res, nil
		}
		return "", ErrNoSuchTx
	}
	pt.decide(decCommit)
	<-pt.done
	return p.mustResolved(txID), nil
}

// Rollback reverts a pending change immediately.
func (p *Protocol) Rollback(txID string) (domain.TxResult, error) {
	pt := p.lookup(txID)
	if pt == nil {
		if res, ok := p.resolvedResult(txID); ok {
			return res, nil
		}
		return "", ErrNoSuchTx
	}
	pt.decide(decRollback)
	<-pt.done
	return p.mustResolved(txID), nil
}

// Wait blocks until the transaction resolves and returns its result.
func (p *Protocol) Wait(txID string) (domain.TxResult, bool) {
	pt := p.lookup(txID)
	if pt != nil {
		<-pt.done
		return p.mustResolved(txID), true
	}
	return p.resolvedResult(txID)
}

// Panic flushes all managed routes and clears ownership (spec §2.1). Idempotent.
func (p *Protocol) Panic(ctx context.Context, actor domain.Actor) error {
	p.applyMu.Lock()
	defer p.applyMu.Unlock()
	err := Panic(ctx, p.prov, p.store)
	result := "panicked"
	if err != nil {
		result = "panic-error"
	}
	p.audit(actor, "panic", result, errString(err), nil, true)
	return err
}

// ReconcileOwnership repairs partial state after a crash (spec §2.5): it makes
// the kernel's managed routes match the ownership DB — re-adding routes we own
// but are missing, and removing kernel routes tagged ours that we no longer own
// (rollback of an interrupted add).
func (p *Protocol) ReconcileOwnership(ctx context.Context) (added, removed int, err error) {
	if p.store == nil {
		return 0, 0, nil
	}
	owned, err := p.store.ListOwned()
	if err != nil {
		return 0, 0, err
	}
	// The kernel's real managed routes — NOT the DB — are the "actual" side here;
	// reconcile converges the kernel to the ownership DB (spec §2.5 crash repair).
	actual := providerManaged(ctx, p.prov)
	ownedKeys := keySet(owned)
	actualKeys := keySet(actual)

	for _, o := range owned {
		if !actualKeys[routing.RouteKey(o.Route)] {
			if e := p.prov.AddRoute(ctx, o); e == nil {
				added++
			}
		}
	}
	for _, a := range actual {
		if !ownedKeys[routing.RouteKey(a.Route)] {
			if e := p.prov.DelRoute(ctx, a); e == nil {
				removed++
			}
		}
	}
	return added, removed, nil
}

// --- internals ---

func (p *Protocol) actualManaged(ctx context.Context) []domain.ManagedRoute {
	if p.store != nil {
		if owned, err := p.store.ListOwned(); err == nil {
			return owned
		}
	}
	return providerManaged(ctx, p.prov)
}

// actualManagedRules returns the policy rules RiftRoute owns. Rules are
// proto-tagged on Linux (and tracked by the fake), so unlike macOS routes they
// are self-identifying and need no DB ownership map.
func (p *Protocol) actualManagedRules(ctx context.Context) []domain.ManagedRule {
	var out []domain.ManagedRule
	for _, fam := range []domain.Family{domain.FamilyV4, domain.FamilyV6} {
		rs, err := p.prov.ListRules(ctx, fam)
		if err != nil {
			continue
		}
		for _, r := range rs {
			if r.Proto == "riftroute" {
				out = append(out, domain.ManagedRule{PolicyRule: r})
			}
		}
	}
	return out
}

func providerManaged(ctx context.Context, prov provider.RouteProvider) []domain.ManagedRoute {
	var out []domain.ManagedRoute
	for _, fam := range []domain.Family{domain.FamilyV4, domain.FamilyV6} {
		rs, err := prov.ListRoutes(ctx, fam)
		if err != nil {
			continue
		}
		for _, r := range rs {
			if r.Owner == domain.OwnerRiftRoute {
				out = append(out, domain.ManagedRoute{Route: r, ProfileID: r.Profile})
			}
		}
	}
	return out
}

func (p *Protocol) applyOwnership(plan domain.Plan, undo bool) {
	if p.store == nil {
		return
	}
	for _, op := range plan.Ops {
		if op.Route == nil {
			continue
		}
		add := op.Kind == domain.OpAddRoute
		if undo {
			add = !add
		}
		if add {
			_ = p.store.AddOwned(*op.Route)
		} else {
			_ = p.store.DelOwned(*op.Route)
		}
	}
}

func (p *Protocol) audit(actor domain.Actor, action, result, reason string, plan *domain.Plan, rollback bool) {
	if p.store == nil {
		return
	}
	_, _ = p.store.AppendAudit(domain.AuditEvent{
		TS: p.clock.Now(), Actor: actor, Action: action, Result: result, Reason: reason, Plan: plan, Rollback: rollback,
	})
}

func (p *Protocol) register(pt *pendingTx) {
	p.txmu.Lock()
	p.pending[pt.id] = pt
	p.txmu.Unlock()
}

func (p *Protocol) lookup(id string) *pendingTx {
	p.txmu.Lock()
	defer p.txmu.Unlock()
	return p.pending[id]
}

func (p *Protocol) resolvedResult(id string) (domain.TxResult, bool) {
	p.txmu.Lock()
	defer p.txmu.Unlock()
	r, ok := p.resolved[id]
	return r, ok
}

func (p *Protocol) mustResolved(id string) domain.TxResult {
	r, _ := p.resolvedResult(id)
	return r
}

func (p *Protocol) nextTxID() string {
	p.txmu.Lock()
	defer p.txmu.Unlock()
	p.idseq++
	return fmt.Sprintf("tx-%d", p.idseq)
}

func (p *Protocol) nextSnapID() string {
	return fmt.Sprintf("snap-%d", p.clock.Now().UnixNano())
}

func keySet(rs []domain.ManagedRoute) map[string]bool {
	m := make(map[string]bool, len(rs))
	for _, r := range rs {
		m[routing.RouteKey(r.Route)] = true
	}
	return m
}

func diffFromPlan(plan domain.Plan) domain.Diff {
	d := domain.Diff{}
	for _, op := range plan.Ops {
		switch op.Kind {
		case domain.OpAddRoute:
			d.Entries = append(d.Entries, domain.DiffEntry{Action: domain.DiffAdd, Route: op.Route.Route})
			d.Adds++
		case domain.OpDelRoute:
			d.Entries = append(d.Entries, domain.DiffEntry{Action: domain.DiffDel, Route: op.Route.Route})
			d.Dels++
		case domain.OpAddRule:
			d.Entries = append(d.Entries, domain.DiffEntry{Action: domain.DiffAdd, Route: ruleAsRoute(op.Rule)})
			d.Adds++
		case domain.OpDelRule:
			d.Entries = append(d.Entries, domain.DiffEntry{Action: domain.DiffDel, Route: ruleAsRoute(op.Rule)})
			d.Dels++
		}
	}
	d.InSync = len(d.Entries) == 0
	return d
}

// ruleAsRoute renders a policy rule as a route-shaped diff entry for display.
func ruleAsRoute(r *domain.ManagedRule) domain.Route {
	if r == nil {
		return domain.Route{}
	}
	return domain.Route{DstCIDR: r.Selector, Iface: "→ table " + r.Table, Family: r.Family, Owner: domain.OwnerRiftRoute}
}

func violationSummary(vs []Violation) string {
	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		parts = append(parts, v.Rule)
	}
	return "guardrails: " + fmt.Sprint(parts)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
