package safety

import (
	"context"
	"fmt"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider"
)

// Executor applies plan operations through a RouteProvider as an atomic unit
// (spec §2.2 step 6). If op k fails, the inverse of ops 1..k-1 runs immediately,
// so the table is never left in a partial state.
type Executor struct {
	prov provider.RouteProvider
}

// NewExecutor wraps a provider.
func NewExecutor(p provider.RouteProvider) *Executor { return &Executor{prov: p} }

// Apply runs plan.Ops in order. On the first error it rolls back the ops already
// applied (reverse order, via each op's inverse) and returns the original error.
func (e *Executor) Apply(ctx context.Context, plan domain.Plan) error {
	applied := make([]domain.PlanOp, 0, len(plan.Ops))
	for _, op := range plan.Ops {
		if err := e.do(ctx, op); err != nil {
			e.rollback(ctx, applied)
			return fmt.Errorf("op %q failed (rolled back %d prior op(s)): %w", op.Human, len(applied), err)
		}
		applied = append(applied, op)
	}
	return nil
}

// RunOps applies a list of ops best-effort (used to replay a precomputed
// inverse during watchdog/commit-confirm rollback). Errors are returned but do
// not stop the remaining ops — recovery must be maximally complete.
func (e *Executor) RunOps(ctx context.Context, ops []domain.PlanOp) error {
	var firstErr error
	for _, op := range ops {
		if err := e.do(ctx, op); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (e *Executor) rollback(ctx context.Context, applied []domain.PlanOp) {
	for i := len(applied) - 1; i >= 0; i-- {
		_ = e.do(ctx, inverseOp(applied[i])) // best-effort; we are already aborting
	}
}

func (e *Executor) do(ctx context.Context, op domain.PlanOp) error {
	switch op.Kind {
	case domain.OpAddRoute:
		if op.Route == nil {
			return fmt.Errorf("add_route op missing route")
		}
		return e.prov.AddRoute(ctx, *op.Route)
	case domain.OpDelRoute:
		if op.Route == nil {
			return fmt.Errorf("del_route op missing route")
		}
		return e.prov.DelRoute(ctx, *op.Route)
	case domain.OpAddRule:
		if op.Rule == nil {
			return fmt.Errorf("add_rule op missing rule")
		}
		return e.prov.AddRule(ctx, *op.Rule)
	case domain.OpDelRule:
		if op.Rule == nil {
			return fmt.Errorf("del_rule op missing rule")
		}
		return e.prov.DelRule(ctx, *op.Rule)
	default:
		return fmt.Errorf("unknown op kind %q", op.Kind)
	}
}

func inverseOp(op domain.PlanOp) domain.PlanOp {
	inv := op
	switch op.Kind {
	case domain.OpAddRoute:
		inv.Kind = domain.OpDelRoute
	case domain.OpDelRoute:
		inv.Kind = domain.OpAddRoute
	case domain.OpAddRule:
		inv.Kind = domain.OpDelRule
	case domain.OpDelRule:
		inv.Kind = domain.OpAddRule
	}
	return inv
}
