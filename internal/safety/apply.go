package safety

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
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
	ErrPanicking       = errors.New("a panic is flushing every managed route; try again")
)

// snapshotRetention caps stored pre-apply snapshots (newest kept).
const snapshotRetention = 50

// routeOpTxPrefix marks journal entries for plan-level route ops (external
// routes, no ownership records). Crash recovery must NOT undo ownership for
// these — there is none — and the prefix is the only signal that survives in
// the WAL across a restart.
const routeOpTxPrefix = "routeop-"

// Store is the slice of persistence the Apply Protocol needs (satisfied by
// *store.Store). Keeping it an interface keeps safety decoupled and testable.
type Store interface {
	AddOwned(domain.ManagedRoute) error
	DelOwned(domain.ManagedRoute) error
	ListOwned() ([]domain.ManagedRoute, error)
	ClearOwned() error
	SaveSnapshot(domain.Snapshot) error
	PruneSnapshots(keep int) error
	ListProfiles() ([]domain.Profile, error)
	AppendAudit(domain.AuditEvent) (int64, error)
	PutPendingTx(id string, plan domain.Plan) error
	ClearPendingTx(id string) error
	ListPendingTx() (map[string]domain.Plan, error)
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
	// SnapshotProfiles is the PRE-change profile set to record in the pre-apply
	// snapshot. Handlers that mutate profiles before calling Apply must pass
	// the set they saw first — otherwise the snapshot would capture the policy
	// including the very change a restore is meant to undo. nil = read the
	// store at snapshot time (correct for applies that don't touch profiles).
	SnapshotProfiles []domain.Profile
	// VetChangesOnly has the guardrails vet only the routes the plan adds
	// (or re-points), not owned routes carried over as they are. For an
	// apply that changes one part of the owned set — a tunnel transition —
	// and must not be refused over a route it doesn't touch: after a network
	// move with auto-apply off, the exclude routes still point at the old
	// gateway, and vetting them would leave the tunnel unable to install or
	// withdraw anything. The unresolved-gateway fail-safe still covers every
	// main-table route the plan adds or removes.
	VetChangesOnly bool
	// Unguarded commits the change as soon as it is applied: no watchdog,
	// guard window or commit-confirm, so nothing rolls it back later. Only
	// for a change that can't cut what the watchdog guards by construction,
	// and whose rollback would do harm — a tunnel transition: a tunnel route
	// never contains the gateway, a resolver in use or an anchor
	// (routing.TunnelRouteBlock), and the guardrails still vet what it adds;
	// rolled back, a withdrawal would re-add an on-link route into an
	// interface that's gone (or another VPN's now), and a connect would lose
	// a live tunnel's routes with nothing to put them back. The journal
	// still covers a crash mid-execution.
	Unguarded bool
	// OnCommit records what the change stands for, once it commits: at once
	// when unguarded, else when its guard window or a confirm commits it —
	// never for a dry run, a refusal, a failure or a rollback. Records land
	// in the order changes settle: a change that goes ahead settles the one
	// still on probation first, and one that changes nothing while another
	// is on probation takes that one's place — its record lands if that one
	// commits, and neither does if it rolls back (the routes are then back
	// to what the record before them describes).
	//
	// It runs before the next apply can build (under the apply lock, or
	// before its transaction reports settled), so it must be quick and must
	// never apply or wait on the protocol. A panic in it is logged; the
	// change stands.
	OnCommit func()
	// BuiltOnRecord says the build read what an earlier change recorded
	// through OnCommit (a tunnel apply puts back what a full one made yield).
	// Built while another change is on probation, whose record isn't in yet,
	// such a set is built again once the apply has settled that change; one
	// that changes nothing records nothing, as it was built from a record
	// that change is about to replace.
	BuiltOnRecord bool
}

// UseGateway points the guardrails and the watchdog at physGW, the physical
// gateway a desired set was built against: PhysGW, and the default anchors.
func (o *Options) UseGateway(physGW netip.Addr) {
	o.PhysGW = physGW
	o.Anchors = DefaultAnchors(physGW)
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
	// ownership: whether this tx's ops are recorded in the ownership map.
	// Policy applies are; plan-level route ops on EXTERNAL routes are not —
	// claiming a user's system route would make panic/crash-repair delete it.
	ownership bool
	decided   chan decision
	cancel    context.CancelFunc
	done      chan struct{}
	result    domain.TxResult
	// onCommit is Options.OnCommit, or the record of a later change that
	// took its place; rec says whether it is still open to that. Both are
	// recMu's.
	onCommit func()
	rec      recState
}

type recState int

const (
	recOpen       recState = iota // on probation: a record may still take its place
	recCommitted                  // its record has run
	recRolledBack                 // its record is dropped
)

// runRecord runs a change's record (Options.OnCommit); the caller holds
// recMu. A panic in it is logged: the change stands whatever its record does.
func (p *Protocol) runRecord(fn func()) {
	if fn == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			p.log.Error("recovered panic recording a committed change", "panic", r)
		}
	}()
	fn()
}

// recordNow records a change that committed at once.
func (p *Protocol) recordNow(opts Options) {
	p.recMu.Lock()
	defer p.recMu.Unlock()
	p.runRecord(opts.OnCommit)
}

// recordUnchanged records a change that changed nothing, built while the
// transactions beside were on probation (see Options.OnCommit): it takes
// the place of those still open, and is dropped if one rolled back — or if
// it was built from a record one of them was about to replace.
func (p *Protocol) recordUnchanged(opts Options, beside []*pendingTx) {
	if opts.OnCommit == nil {
		return
	}
	p.recMu.Lock()
	defer p.recMu.Unlock()
	if len(beside) > 0 && opts.BuiltOnRecord {
		return
	}
	var open []*pendingTx
	for _, pt := range beside {
		switch pt.rec {
		case recOpen:
			open = append(open, pt)
		case recRolledBack:
			return
		}
	}
	for _, pt := range open {
		pt.onCommit = opts.OnCommit
	}
	if len(open) == 0 {
		p.runRecord(opts.OnCommit)
	}
}

// settleRecord closes pt's record as it resolves: runs it if it commits,
// drops it otherwise.
func (p *Protocol) settleRecord(pt *pendingTx, commit bool) {
	p.recMu.Lock()
	defer p.recMu.Unlock()
	if pt.rec != recOpen {
		return
	}
	fn := pt.onCommit
	pt.onCommit = nil
	if !commit {
		pt.rec = recRolledBack
		return
	}
	pt.rec = recCommitted
	p.runRecord(fn)
}

// onProbation returns the policy transactions still on probation — those
// whose records (Options.OnCommit) aren't in yet.
func (p *Protocol) onProbation() []*pendingTx {
	p.txmu.Lock()
	defer p.txmu.Unlock()
	var out []*pendingTx
	for _, pt := range p.pending {
		if pt.ownership {
			out = append(out, pt)
		}
	}
	return out
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

	applyMu  applyLock  // serializes applies; see lockApply
	recMu    sync.Mutex // orders the changes' records (Options.OnCommit)
	txmu     sync.Mutex
	pending  map[string]*pendingTx
	resolved map[string]domain.TxResult
	idseq    int
	lastTx   time.Time // start of the most recent transaction (txmu)

	panicking atomic.Int32 // panics in progress: every apply is refused

	onSettled atomic.Pointer[func()] // see SetOnSettled
}

// TryQuiesce takes the apply lock if the daemon is quiet — nothing being
// applied, nothing awaiting confirmation, no change started within quiet —
// and keeps it until release is called (the updater holds it from the swap
// until the process exits, so no change can start in between). When it isn't
// quiet it says why and holds nothing.
func (p *Protocol) TryQuiesce(quiet time.Duration) (release func(), ok bool, why string) {
	if !p.applyMu.TryLock() {
		return nil, false, "a change is being applied"
	}
	p.txmu.Lock()
	pending, last := len(p.pending), p.lastTx
	p.txmu.Unlock()
	switch {
	case pending > 0:
		p.applyMu.Unlock()
		return nil, false, "a change is awaiting confirmation"
	case !last.IsZero() && p.clock.Now().Sub(last) < quiet:
		p.applyMu.Unlock()
		return nil, false, fmt.Sprintf("a change was made in the last %s", quiet.Round(time.Minute))
	}
	var once sync.Once
	return func() { once.Do(p.applyMu.Unlock) }, true, ""
}

// Busy reports whether a change is being applied or is still on probation
// (awaiting confirmation, watchdog armed), and when the last one started.
// The updater waits for quiet before replacing the daemon.
func (p *Protocol) Busy() (busy bool, lastTx time.Time) {
	if !p.applyMu.TryLock() {
		busy = true
	} else {
		p.applyMu.Unlock()
	}
	p.txmu.Lock()
	defer p.txmu.Unlock()
	return busy || len(p.pending) > 0, p.lastTx
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
		applyMu: newApplyLock(), pending: map[string]*pendingTx{}, resolved: map[string]domain.TxResult{},
	}
}

// Plan builds the reconcile plan + diff for desired state without applying — the
// dry-run preview (spec §2.2 step 4).
func (p *Protocol) Plan(ctx context.Context, desiredRoutes []domain.ManagedRoute, desiredRules []domain.ManagedRule) (domain.Plan, domain.Diff) {
	actual := p.installed(ctx, p.actualManaged(ctx), desiredRoutes)
	plan := routing.Reconcile(desiredRoutes, actual, desiredRules, p.actualManagedRules(ctx), p.platform)
	return plan, diffFromPlan(plan)
}

// Apply runs the full Apply Protocol. For DryRun it returns the preview. On
// success it executes atomically, arms the watchdog + commit-confirm, and
// returns a pending transaction (resolved later via Confirm/timeout/watchdog).
//
// ctx bounds the wait for the apply lock (see lockApply). Once an apply holds
// the lock it runs to the end on ctx's values, not its deadline: every
// provider command has a timeout of its own, and a change cut off half-way —
// its rollback failing on the same expired context — would leave the table
// half-changed.
func (p *Protocol) Apply(ctx context.Context, desired []domain.ManagedRoute, desiredRules []domain.ManagedRule, opts Options) (Result, error) {
	if err := p.lockApply(ctx); err != nil {
		return Result{Status: domain.TxFailed, Error: err.Error()}, err
	}
	defer p.applyMu.Unlock()
	ctx = context.WithoutCancel(ctx)
	return p.apply(ctx, p.actualManaged(ctx), desired, desiredRules, opts, p.onProbation(), nil)
}

// lockApply takes the apply lock unless a panic is in progress — checked
// before waiting (a panic's first step may itself be waiting on an apply)
// and again after (an apply queued behind the panic's flush must not undo
// it) — or ctx ends while it waits: the caller stopped waiting, so the change
// is dropped rather than made later behind its back.
func (p *Protocol) lockApply(ctx context.Context) error {
	if p.panicking.Load() > 0 {
		return ErrPanicking
	}
	if err := p.applyMu.LockCtx(ctx); err != nil {
		return fmt.Errorf("gave up waiting for the change in progress: %w", err)
	}
	if p.panicking.Load() > 0 {
		p.applyMu.Unlock()
		return ErrPanicking
	}
	return nil
}

// Build derives the desired routes and rules from owned — the routes
// RiftRoute owns right now (the ownership map) — on the apply's ctx. It sets
// what in opts depends on the network (see Options.UseGateway) from the same
// reads the set is built from: after a network move, a set built for the new
// gateway must not be vetted and guarded against the old one.
type Build func(ctx context.Context, owned []domain.ManagedRoute, opts *Options) ([]domain.ManagedRoute, []domain.ManagedRule, error)

// ApplyBuilt runs the Apply Protocol like Apply, but derives desired state
// under the apply lock: no other apply can land between the reads it is
// built from and the change, so it can't undo a change made moments before
// (a tunnel transition and an auto-apply racing would otherwise each revert
// the other). A build error aborts before anything is touched.
func (p *Protocol) ApplyBuilt(ctx context.Context, build Build, opts Options) (Result, error) {
	if err := p.lockApply(ctx); err != nil {
		return Result{Status: domain.TxFailed, Error: err.Error()}, err
	}
	defer p.applyMu.Unlock()
	ctx = context.WithoutCancel(ctx) // see Apply
	return p.applyBuilt(ctx, build, opts, p.onProbation())
}

// applyBuilt builds and applies; beside are the transactions on probation
// as the build starts. The caller holds applyMu.
func (p *Protocol) applyBuilt(ctx context.Context, build Build, opts Options, beside []*pendingTx) (Result, error) {
	base := opts
	owned := p.actualManaged(ctx)
	desired, desiredRules, err := build(ctx, owned, &opts)
	if err != nil {
		return Result{Status: domain.TxFailed, Error: err.Error()}, err
	}
	var again func() (Result, error)
	if len(beside) > 0 && opts.BuiltOnRecord {
		// Built from a record the changes beside may be about to replace:
		// once they're settled, build again from what they recorded.
		again = func() (Result, error) { return p.applyBuilt(ctx, build, base, nil) }
	}
	return p.apply(ctx, owned, desired, desiredRules, opts, beside, again)
}

// apply is the body of Apply and ApplyBuilt; the caller holds applyMu.
// beside are the transactions on probation when desired was built; again,
// if set, builds and applies afresh once they're settled.
func (p *Protocol) apply(ctx context.Context, owned, desired []domain.ManagedRoute, desiredRules []domain.ManagedRule, opts Options, beside []*pendingTx, again func() (Result, error)) (Result, error) {
	actual := p.installed(ctx, owned, desired)
	plan := routing.Reconcile(desired, actual, desiredRules, p.actualManagedRules(ctx), p.platform)
	diff := diffFromPlan(plan)

	if opts.DryRun {
		return Result{Plan: plan, Diff: diff, Status: domain.TxPending}, nil
	}

	// Guardrails (§2.4) — refuse before touching anything.
	var vet *domain.Plan
	if opts.VetChangesOnly {
		vet = &plan
	}
	if vs := checkGuardrails(ctx, p.prov, desired, vet, opts.PhysGW); len(vs) > 0 {
		p.audit(opts.Actor, "apply", "refused", violationSummary(vs), &plan, false)
		return Result{Plan: plan, Diff: diff, Violations: vs, Status: domain.TxFailed, Error: ErrGuardrail.Error()}, ErrGuardrail
	}

	if len(plan.Ops) == 0 {
		p.recordUnchanged(opts, beside)
		return Result{Plan: plan, Diff: diff, Status: domain.TxCommitted}, nil
	}

	if err := p.supersedePending(); err != nil {
		return Result{Plan: plan, Diff: diff, Status: domain.TxFailed, Error: err.Error()}, err
	}
	if again != nil {
		return again()
	}
	p.takeSnapshot(ctx, opts)

	return p.executePlan(ctx, "apply", plan, diff, opts, true)
}

// supersedePending serializes applies (spec §11): an interactive change
// awaiting confirmation blocks new applies; a non-interactive change is just
// guarding in the background, so a new apply supersedes it (commit it, stop
// its guard).
func (p *Protocol) supersedePending() error {
	p.txmu.Lock()
	var supersede []*pendingTx
	for _, pt := range p.pending {
		if pt.interactive {
			p.txmu.Unlock()
			return ErrApplyInProgress
		}
		supersede = append(supersede, pt)
	}
	p.txmu.Unlock()
	for _, pt := range supersede {
		pt.decide(decCommit)
		<-pt.done
	}
	return nil
}

// takeSnapshot records the restore point of last resort behind the inverse.
// The profile set rides along: that is what a user-facing "restore" brings
// back — the reconciler then converges routes to it. Retention-pruned so
// years of applies can't grow the DB unboundedly.
func (p *Protocol) takeSnapshot(ctx context.Context, opts Options) {
	if p.store == nil {
		return
	}
	snap, err := Capture(ctx, p.prov, p.nextSnapID(), "pre-apply", func() domain.Snapshot {
		return domain.Snapshot{CreatedAt: p.clock.Now()}
	})
	if err != nil {
		return
	}
	snap.Profiles = opts.SnapshotProfiles
	if snap.Profiles == nil {
		if profs, perr := p.store.ListProfiles(); perr == nil {
			if profs == nil {
				profs = []domain.Profile{} // empty ≠ uncaptured
			}
			snap.Profiles = profs
		}
	}
	_ = p.store.SaveSnapshot(snap)
	_ = p.store.PruneSnapshots(snapshotRetention)
}

// ApplyPlan runs a hand-built plan (single-route edit/delete of routes
// RiftRoute does NOT manage) through the same machinery as a policy apply:
// snapshot → WAL → atomic execute → watchdog + commit-confirm. Ownership is
// deliberately NOT recorded — these are user edits of system state, so panic
// and crash-repair must leave the results alone; the journaled inverse is
// what protects the change until it's confirmed.
func (p *Protocol) ApplyPlan(ctx context.Context, action string, plan domain.Plan, opts Options) (Result, error) {
	if err := p.lockApply(ctx); err != nil {
		return Result{Plan: plan, Status: domain.TxFailed, Error: err.Error()}, err
	}
	defer p.applyMu.Unlock()
	ctx = context.WithoutCancel(ctx) // see Apply

	diff := diffFromPlan(plan)
	if opts.DryRun {
		return Result{Plan: plan, Diff: diff, Status: domain.TxPending}, nil
	}
	if vs := checkPlanGuardrails(plan); len(vs) > 0 {
		p.audit(opts.Actor, action, "refused", violationSummary(vs), &plan, false)
		return Result{Plan: plan, Diff: diff, Violations: vs, Status: domain.TxFailed, Error: ErrGuardrail.Error()}, ErrGuardrail
	}
	if len(plan.Ops) == 0 {
		p.recordUnchanged(opts, p.onProbation())
		return Result{Plan: plan, Diff: diff, Status: domain.TxCommitted}, nil
	}
	if err := p.supersedePending(); err != nil {
		return Result{Plan: plan, Diff: diff, Status: domain.TxFailed, Error: err.Error()}, err
	}
	p.takeSnapshot(ctx, opts)
	return p.executePlan(ctx, action, plan, diff, opts, false)
}

// checkPlanGuardrails vets a hand-built plan: it must never remove a
// main-table default route without adding one back in the same transaction —
// that is the one edit whose brief absence can strand the host entirely. The
// default is detected by PREFIX LENGTH (0 significant bits) after parsing, not
// by string equality: the kernel matches a route by its masked prefix, so a
// non-canonical "128.0.0.0/0" deletes the real default just the same and must
// not slip past the guard.
func checkPlanGuardrails(plan domain.Plan) []Violation {
	removed := map[string]bool{} // family → a default delete is pending
	for _, op := range plan.Ops {
		if op.Route == nil || op.Route.Table != "" {
			continue
		}
		pfx, err := netip.ParsePrefix(op.Route.DstCIDR)
		if err != nil || pfx.Bits() != 0 {
			continue
		}
		fam := "v4"
		if pfx.Addr().Is6() {
			fam = "v6"
		}
		switch op.Kind {
		case domain.OpDelRoute:
			removed[fam] = true
		case domain.OpAddRoute:
			delete(removed, fam)
		}
	}
	var vs []Violation
	for fam := range removed {
		def := "0.0.0.0/0"
		if fam == "v6" {
			def = "::/0"
		}
		vs = append(vs, Violation{
			Rule:   "keep-default-route",
			Detail: "refusing to remove the " + fam + " default route (" + def + ") without a replacement — edit it instead",
		})
	}
	return vs
}

// executePlan journals, executes, and arms the watchdog/commit-confirm for a
// computed plan — the shared tail of Apply and ApplyPlan. ownership controls
// whether the delta is recorded in (and rolled back out of) the ownership map.
func (p *Protocol) executePlan(ctx context.Context, action string, plan domain.Plan, diff domain.Diff, opts Options, ownership bool) (Result, error) {
	// Write-ahead journal: record how to undo this tx BEFORE touching the kernel.
	// If we're SIGKILLed/power-lost between here and COMMIT, startup RecoverPending
	// replays the inverse — the only crash-safe recovery on macOS, where kernel
	// routes carry no owner tag to reattribute them.
	txID := p.nextTxID()
	p.txmu.Lock()
	p.lastTx = p.clock.Now()
	p.txmu.Unlock()
	if !ownership {
		txID = routeOpTxPrefix + strings.TrimPrefix(txID, "tx-")
	}
	if p.store != nil {
		if err := p.store.PutPendingTx(txID, plan); err != nil {
			p.log.Warn("could not journal pending tx; proceeding without crash-recovery for it", "tx", txID, "err", err)
		}
	}

	// EXECUTE atomically; on error the executor has already rolled back.
	exec := NewExecutor(p.prov)
	if err := exec.Apply(ctx, plan); err != nil {
		p.clearPending(txID)
		p.audit(opts.Actor, action, string(domain.TxFailed), err.Error(), &plan, true)
		return Result{Plan: plan, Diff: diff, Status: domain.TxFailed, Error: err.Error()}, nil
	}

	// Record ownership for the applied delta and audit the applied change.
	if ownership {
		p.applyOwnership(plan, false)
	}
	p.audit(opts.Actor, action, "applied", "", &plan, false)

	if opts.Unguarded {
		p.clearPending(txID)
		p.txmu.Lock()
		p.resolved[txID] = domain.TxCommitted
		p.txmu.Unlock()
		p.audit(opts.Actor, "confirm", "committed", "unguarded", nil, false)
		p.recordNow(opts)
		return Result{TxID: txID, Plan: plan, Diff: diff, Status: domain.TxCommitted}, nil
	}

	// ARM watchdog + commit-confirm and resolve in the background.
	ctxTx, cancel := context.WithCancel(context.Background())
	pt := &pendingTx{id: txID, plan: plan, interactive: opts.Interactive, ownership: ownership, decided: make(chan decision, 4), cancel: cancel, done: make(chan struct{}), onCommit: opts.OnCommit}
	p.register(pt)

	prober := p.newProber()
	guardFirst := p.clock.After(opts.ProbeInterval) // registered synchronously (fake-clock safe)
	decisionTimer := p.clock.After(opts.window())
	wd := NewWatchdog(p.clock, prober, opts.Anchors, opts.K, opts.ProbeInterval, func() { pt.decide(decRollback) })
	p.goSafe("watchdog", func() { wd.Run(ctxTx, guardFirst) })
	p.goSafe("decision-timer", func() {
		select {
		case <-ctxTx.Done():
		case <-decisionTimer:
			if opts.Interactive {
				pt.decide(decRollback) // missed confirm → auto-revert
			} else {
				pt.decide(decCommit) // guard window elapsed cleanly → commit
			}
		}
	})
	go p.resolve(pt, opts.Actor)

	return Result{TxID: txID, Plan: plan, Diff: diff, Status: domain.TxPending, NeedsConfirm: opts.Interactive}, nil
}

// goSafe runs fn in a goroutine that recovers from panics — an unrecovered panic
// in ANY goroutine crashes the whole daemon, which would kill an armed watchdog
// and strand the user. Background signalers just log; the tx-resolving goroutine
// has its own panic path (see resolve) that forces a rollback.
func (p *Protocol) goSafe(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				p.log.Error("recovered panic in daemon goroutine", "where", name, "panic", r)
			}
		}()
		fn()
	}()
}

func (p *Protocol) resolve(pt *pendingTx, actor domain.Actor) {
	// A panic here (e.g. in the provider during rollback) must never leave a tx
	// half-resolved with a dead watchdog. Recover and force a best-effort revert
	// so the host converges to the safe (pre-change) state.
	defer func() {
		if r := recover(); r != nil {
			p.log.Error("recovered panic resolving tx; forcing rollback", "tx", pt.id, "panic", r)
			p.settleRecord(pt, false)
			inverse := withoutTunnelLinks(pt.plan.Inverse)
			_ = NewExecutor(p.prov).RunOps(context.Background(), inverse)
			if pt.ownership {
				for _, op := range inverse {
					p.recordOwnership(op)
				}
			}
			pt.result = domain.TxRolledBack
			p.finishTx(pt)
		}
	}()

	d := <-pt.decided
	pt.cancel() // stop watchdog + decision timer
	if d == decCommit {
		pt.result = domain.TxCommitted
		p.clearPending(pt.id) // resolved cleanly → no crash-recovery needed
		p.audit(actor, "confirm", "committed", "", nil, false)
		p.settleRecord(pt, true) // before it reports settled: see Options.OnCommit
	} else {
		p.settleRecord(pt, false)
		if left, rbErr := p.rollBack(pt); rbErr != nil {
			// The kernel wasn't fully reverted. The ownership records follow
			// what was; the journal KEEPS what wasn't, so Panic / startup
			// RecoverPending can retry it — report the true outcome rather
			// than a false "rolled back".
			if p.store != nil {
				if err := p.store.PutPendingTx(pt.id, left); err != nil {
					p.log.Warn("could not narrow the journal to the incomplete rollback", "tx", pt.id, "err", err)
				}
			}
			pt.result = domain.TxRolledBack
			p.audit(actor, "rollback", "rollback_incomplete", rbErr.Error(), nil, true)
			p.finishTx(pt)
			return
		}
		p.clearPending(pt.id)
		pt.result = domain.TxRolledBack
		p.audit(actor, "rollback", "rolled_back", "watchdog or missed confirm", nil, true)
	}
	p.finishTx(pt)
}

// rollBack replays a transaction's inverse op by op, less the re-adds of a
// tunnel's on-link routes (see withoutTunnelLinks): the tunnel may be gone
// and its interface name another VPN's by now — the tunnels re-apply their
// routes once the transaction has settled. The ownership map follows each op
// that went through, so it agrees with the kernel even when some fail (a pin
// re-added while the on-link route beside it failed must not be left in the
// kernel unrecorded). It returns what failed as a plan of its own: those ops'
// forward effect is still in place, and left.Inverse still undoes it.
func (p *Protocol) rollBack(pt *pendingTx) (left domain.Plan, err error) {
	exec := NewExecutor(p.prov)
	ctx := provider.WithTableCache(context.Background())
	for _, op := range withoutTunnelLinks(pt.plan.Inverse) {
		if e := exec.do(ctx, op); e != nil {
			if err == nil {
				err = e
			}
			left.Inverse = append(left.Inverse, op)
			continue
		}
		if pt.ownership {
			p.recordOwnership(op)
		}
	}
	for i := len(left.Inverse) - 1; i >= 0; i-- {
		left.Ops = append(left.Ops, inverseOp(left.Inverse[i]))
	}
	return left, err
}

func (p *Protocol) clearPending(id string) {
	if p.store != nil {
		_ = p.store.ClearPendingTx(id)
	}
}

// finishTx records the resolved result and unblocks Wait/Confirm/Rollback,
// tolerating a double-call from the panic-recovery path.
func (p *Protocol) finishTx(pt *pendingTx) {
	p.txmu.Lock()
	if _, done := p.resolved[pt.id]; done {
		p.txmu.Unlock()
		return
	}
	p.resolved[pt.id] = pt.result
	delete(p.pending, pt.id)
	p.txmu.Unlock()
	close(pt.done)
	p.settled()
}

// SetOnSettled installs fn, called whenever a transaction on probation
// resolves — its guard window commits it, a watchdog or a missed confirm
// rolls it back, it is confirmed or rolled back by hand, a newer apply or a
// panic settles it — and after a panic has flushed. Those are the moments an
// apply refused meanwhile (ErrApplyInProgress, ErrPanicking) can go through,
// and a rollback may have withdrawn routes the tunnels still want: the daemon
// re-applies its tunnels' routes from it. A change that commits at once
// (Options.Unguarded) or fails never had anyone waiting on it and doesn't
// call it. fn runs on a goroutine of its own, never under the Protocol's
// locks, so it may apply. nil removes it.
func (p *Protocol) SetOnSettled(fn func()) {
	if fn == nil {
		p.onSettled.Store(nil)
		return
	}
	p.onSettled.Store(&fn)
}

// settled calls the SetOnSettled hook, if any.
func (p *Protocol) settled() {
	if fn := p.onSettled.Load(); fn != nil {
		p.goSafe("on-settled", *fn)
	}
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
	return p.PanicWith(ctx, actor, PanicSteps{})
}

// PanicSteps are what a panic runs besides the flush.
type PanicSteps struct {
	// Before runs first, while every apply is refused: the daemon takes its
	// tunnels down there, and a tunnel going down re-applies the surviving
	// tunnels' routes, which must not land around the flush.
	Before func(context.Context)
	// Flushing runs under the apply lock right before the flush, once the
	// guards still armed are settled and their records (Options.OnCommit)
	// are in: for dropping what those record about the routes the flush
	// removes. No change can record anything after it.
	Flushing func()
}

// PanicWith is Panic with steps of the caller's around the flush (see
// PanicSteps). Guards still armed are settled before the flush, so none can
// roll back afterwards and re-add what it removed.
func (p *Protocol) PanicWith(ctx context.Context, actor domain.Actor, steps PanicSteps) error {
	err := p.panicWith(ctx, actor, steps)
	p.settled() // applies are accepted again
	return err
}

func (p *Protocol) panicWith(ctx context.Context, actor domain.Actor, steps PanicSteps) error {
	p.panicking.Add(1)
	defer p.panicking.Add(-1)
	if steps.Before != nil {
		steps.Before(ctx)
	}
	p.applyMu.Lock()
	defer p.applyMu.Unlock()
	p.settleForPanic()
	if steps.Flushing != nil {
		steps.Flushing()
	}
	// The flush runs to the end whether or not its caller still waits (see
	// Apply): cut off half-way, what it failed to remove stays recorded.
	err := Panic(context.WithoutCancel(ctx), p.prov, p.store)
	result := "panicked"
	if err != nil {
		result = "panic-error"
	}
	p.audit(actor, "panic", result, errString(err), nil, true)
	return err
}

// settleForPanic commits the policy transactions still on probation: the
// flush is about to remove every managed route, and a guard firing afterwards
// would replay an inverse that re-adds some. Plan-level edits of routes
// RiftRoute doesn't own aren't flushed, so they keep their guard.
func (p *Protocol) settleForPanic() {
	p.txmu.Lock()
	var settle []*pendingTx
	for _, pt := range p.pending {
		if pt.ownership {
			settle = append(settle, pt)
		}
	}
	p.txmu.Unlock()
	for _, pt := range settle {
		pt.decide(decCommit)
		<-pt.done
	}
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

// ShutdownResolve resolves in-flight transactions for a GRACEFUL shutdown, so a
// clean reboot doesn't trip crash-recovery: a guarding non-interactive change is
// committed (it was applied and working — routing should survive the reboot), an
// unconfirmed interactive change is rolled back (the user never confirmed it).
// Only an actual crash — which never runs this — leaves the journal for
// RecoverPending to revert. Idempotent; safe to call once on the way out.
func (p *Protocol) ShutdownResolve() {
	p.txmu.Lock()
	pts := make([]*pendingTx, 0, len(p.pending))
	for _, pt := range p.pending {
		pts = append(pts, pt)
	}
	p.txmu.Unlock()
	for _, pt := range pts {
		if pt.interactive {
			pt.decide(decRollback)
		} else {
			pt.decide(decCommit)
		}
		<-pt.done
	}
}

// RecoverPending is the startup fail-safe for the write-ahead journal. Any tx
// still journaled was in flight — or on probation with its watchdog armed — when
// the daemon last stopped (crash/power loss/SIGKILL). We can't know it was safe,
// so we replay its inverse to revert to the pre-change state and clear it. This
// is the only crash recovery that works on macOS, where kernel routes carry no
// owner tag to reattribute. Run it on startup BEFORE ReconcileOwnership. A
// tunnel's on-link routes are never re-added (see withoutTunnelLinks).
func (p *Protocol) RecoverPending(ctx context.Context) (int, error) {
	if p.store == nil {
		return 0, nil
	}
	// Readable entries are recovered even when others are not: an entry this
	// build can't interpret (a newer format, after an update rollback) stays in
	// the journal for the binary that wrote it, and the error is returned so
	// the daemon reports it rather than quietly running on.
	pend, err := p.store.ListPendingTx()
	if pend == nil && err != nil {
		return 0, err
	}
	exec := NewExecutor(p.prov)
	n := 0
	for id, plan := range pend {
		_ = exec.RunOps(ctx, withoutTunnelLinks(plan.Inverse)) // best-effort revert to baseline
		if !strings.HasPrefix(id, routeOpTxPrefix) {
			p.applyOwnership(plan, true) // undo any ownership records it wrote
		}
		_ = p.store.ClearPendingTx(id)
		p.audit(domain.ActorDaemon, "recover", "reverted_pending",
			"crash recovery: reverted in-flight transaction "+id, nil, true)
		n++
	}
	return n, err
}

// DropTunnelRoutes forgets the routes a previous run's tunnels left: at
// startup no tunnel is running, so every one is stale. Run it after
// RecoverPending and before ReconcileOwnership, which would otherwise re-add
// them — an on-link route by interface name, into whatever interface has that
// name now (after a reboot, the tunnel's utun5 may be another VPN's).
//
// An on-link route's record is only dropped: the route went with its
// interface (or goes when the orphaned openvpn is stopped), and deleting it by
// name could hit the new owner's. A server pin goes via the physical gateway
// and outlives its tunnel, so it is withdrawn from the kernel too; one that
// won't delete keeps its record, for the tunnels' startup resync to withdraw
// through the Apply Protocol. A tunnel re-pins when it connects.
func (p *Protocol) DropTunnelRoutes(ctx context.Context) (int, error) {
	if p.store == nil {
		return 0, nil
	}
	p.applyMu.Lock()
	defer p.applyMu.Unlock()
	owned, err := p.store.ListOwned()
	if err != nil {
		return 0, err
	}
	ctx = provider.WithTableCache(ctx)
	n := 0
	for _, o := range owned {
		if !strings.HasPrefix(o.ProfileID, routing.TunnelProfilePrefix) {
			continue
		}
		if o.Gateway != "" {
			if err := p.prov.DelRoute(ctx, o); err != nil {
				p.log.Warn("could not withdraw a previous run's tunnel pin; retrying later", "route", o.DstCIDR, "err", err)
				continue
			}
		}
		if err := p.store.DelOwned(o); err == nil {
			n++
		}
	}
	if n > 0 {
		p.audit(domain.ActorDaemon, "recover", "dropped_tunnel_routes",
			fmt.Sprintf("startup: forgot %d route(s) left by the previous run's tunnels", n), nil, false)
	}
	return n, nil
}

// withoutTunnelLinks drops the re-adds of tunnel on-link routes from a
// replayed inverse. In crash recovery no tunnel runs yet, and such a route
// would go into whatever interface has the recorded name now
// (DropTunnelRoutes then drops their records); in a guard's rollback the
// tunnel may be gone too, and the tunnels re-apply what they still route
// once it has settled (SetOnSettled).
func withoutTunnelLinks(ops []domain.PlanOp) []domain.PlanOp {
	out := ops[:0:0]
	for _, op := range ops {
		if op.Kind == domain.OpAddRoute && op.Route != nil && op.Route.Gateway == "" &&
			strings.HasPrefix(op.Route.ProfileID, routing.TunnelProfilePrefix) {
			continue
		}
		out = append(out, op)
	}
	return out
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

// installed is the "actual" side of a reconcile: the owned routes, less the
// tunnel routes desired still wants that the kernel dropped with their
// interface — so the plan puts those back (routing.VerifyTunnelRoutes).
func (p *Protocol) installed(ctx context.Context, owned, desired []domain.ManagedRoute) []domain.ManagedRoute {
	return routing.VerifyTunnelRoutes(owned, desired, func(fam domain.Family) ([]domain.Route, error) {
		return p.prov.ListRoutes(ctx, fam)
	})
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
	for _, op := range plan.Ops {
		if undo {
			op = inverseOp(op)
		}
		p.recordOwnership(op)
	}
}

// recordOwnership records what a route op that went through did: an added
// route is RiftRoute's, a deleted one no longer is.
func (p *Protocol) recordOwnership(op domain.PlanOp) {
	if p.store == nil || op.Route == nil {
		return
	}
	switch op.Kind {
	case domain.OpAddRoute:
		_ = p.store.AddOwned(*op.Route)
	case domain.OpDelRoute:
		_ = p.store.DelOwned(*op.Route)
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
	dest := "→ table " + r.Table
	if r.RouteToIface != "" { // macOS PF route-to
		dest = "→ " + r.RouteToIface
	}
	return domain.Route{DstCIDR: r.Selector, Iface: dest, Family: r.Family, Owner: domain.OwnerRiftRoute}
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
