// Package progress carries a change's live steps from where the work is done
// (the Apply Protocol, the domain lookups) to whoever shows them (the API's
// event stream, for the app that asked), through the request's context. With
// no reporter in the context, reporting does nothing.
package progress

import (
	"context"
	"sync"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// Header is the request header a client tags its change with.
const Header = "X-RR-Progress"

// ValidID reports whether id can tag a change: 1–64 letters, digits, - or _.
func ValidID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

type key struct{}

// minGap spaces a step's count updates (a long list's routes are changed a
// few milliseconds apart); a new step, and a step's last item, always go out.
const minGap = 100 * time.Millisecond

type reporter struct {
	id   string
	emit func(domain.ApplyProgress)

	mu   sync.Mutex
	step domain.ApplyStep
	last time.Time
}

// With returns ctx carrying a reporter that emits the change's steps as id.
func With(ctx context.Context, id string, emit func(domain.ApplyProgress)) context.Context {
	return context.WithValue(ctx, key{}, &reporter{id: id, emit: emit})
}

// Detach returns ctx without its reporter: for work a change's request does
// that isn't the change (the state it broadcasts once it's done).
func Detach(ctx context.Context) context.Context {
	return context.WithValue(ctx, key{}, (*reporter)(nil))
}

// Report says the change in ctx is at step, done of total (0, 0 for a step
// without a count).
func Report(ctx context.Context, step domain.ApplyStep, done, total int) {
	r, _ := ctx.Value(key{}).(*reporter)
	if r == nil {
		return
	}
	now := time.Now()
	r.mu.Lock()
	send := step != r.step || done >= total || now.Sub(r.last) >= minGap
	if send {
		r.step, r.last = step, now
	}
	r.mu.Unlock()
	if send {
		r.emit(domain.ApplyProgress{ID: r.id, Step: step, Done: done, Total: total})
	}
}

// Counter reports a counted step as its items finish, from any goroutine.
type Counter struct {
	ctx   context.Context
	step  domain.ApplyStep
	total int
	mu    sync.Mutex
	done  int
}

// Count starts a counted step of total items (reported at 0).
func Count(ctx context.Context, step domain.ApplyStep, total int) *Counter {
	Report(ctx, step, 0, total)
	return &Counter{ctx: ctx, step: step, total: total}
}

// Add marks one more item done.
func (c *Counter) Add() {
	c.mu.Lock()
	c.done++
	done := c.done
	c.mu.Unlock()
	Report(c.ctx, c.step, done, c.total)
}
