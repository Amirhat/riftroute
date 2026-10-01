package safety

import (
	"context"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// timing marks when an apply got past each of its parts, for the audit and
// the log: how long a change waited for another, how long its desired state
// took to build (the profiles' domain lookups are in it), to vet, and to
// make. Carried in the apply's context; the wall clock, not Protocol.clock —
// it measures, it decides nothing.
type timing struct {
	start, locked, built, vetted, done time.Time
}

type timingKey struct{}

// startTiming starts timing the apply on ctx.
func startTiming(ctx context.Context) context.Context {
	return context.WithValue(ctx, timingKey{}, &timing{start: time.Now()})
}

func timingOf(ctx context.Context) *timing {
	t, _ := ctx.Value(timingKey{}).(*timing)
	return t
}

// mark stamps now into the part f of the apply on ctx (none: nothing).
func mark(ctx context.Context, f func(*timing) *time.Time) {
	if t := timingOf(ctx); t != nil {
		*f(t) = time.Now()
	}
}

func (t *timing) summary() *domain.ApplyTiming {
	if t == nil || t.done.IsZero() {
		return nil
	}
	// A part that wasn't marked (an apply with nothing to build) took no time.
	at := func(x, prev time.Time) time.Time {
		if x.IsZero() {
			return prev
		}
		return x
	}
	locked := at(t.locked, t.start)
	built := at(t.built, locked)
	vetted := at(t.vetted, built)
	// Each part is the difference of whole milliseconds since the start,
	// so the parts always add up to the total (rounding each part on its
	// own can lose a millisecond between them).
	since := func(x time.Time) int64 { return x.Sub(t.start).Milliseconds() }
	l, b, v, d := since(locked), since(built), since(vetted), since(t.done)
	return &domain.ApplyTiming{TotalMS: d, WaitMS: l, BuildMS: b - l, CheckMS: v - b, ExecMS: d - v}
}

// slowApply is how long a change may take before the log says so, with its
// parts.
const slowApply = 2 * time.Second
