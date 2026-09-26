package tunnel

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// applier runs the tunnels' route applies one at a time, on a goroutine of
// its own. Callers only ask for one: a management reader must never block on
// the Apply Protocol's lock, which an interactive change awaiting
// confirmation holds for minutes — and the updater holds until the daemon
// restarts. A refused apply is retried until it goes through or a newer
// request replaces it.
type applier struct {
	apply func(ctx context.Context) error
	log   *slog.Logger

	mu      sync.Mutex
	changed *sync.Cond
	want    uint64 // requests made
	done    uint64 // the latest request an apply has covered
	lastErr error

	kick chan struct{}
	stop chan struct{}
	once sync.Once
}

// Retry pacing for a refused apply: every applyRetryEvery at first, backing
// off to applyRetryMax. It never gives up — an interactive change awaiting
// confirmation can hold the protocol for as long as its timeout — but a
// settled transaction or a new request retries at once.
var (
	applyRetryEvery = 3 * time.Second
	applyRetryMax   = 30 * time.Second
	applyTimeout    = 30 * time.Second
)

func newApplier(apply func(ctx context.Context) error, log *slog.Logger) *applier {
	a := &applier{apply: apply, log: log, kick: make(chan struct{}, 1), stop: make(chan struct{})}
	a.changed = sync.NewCond(&a.mu)
	go a.loop()
	return a
}

// request asks for an apply of the tunnels' current routes and returns its
// ticket. It never blocks.
func (a *applier) request() uint64 {
	a.mu.Lock()
	a.want++
	n := a.want
	a.mu.Unlock()
	select {
	case a.kick <- struct{}{}:
	default: // one is already pending; it will see this request
	}
	return n
}

// wait blocks until an apply that started after ticket n finished, or ctx
// ends, and returns that apply's error.
func (a *applier) wait(ctx context.Context, n uint64) error {
	stop := context.AfterFunc(ctx, func() {
		a.mu.Lock()
		a.changed.Broadcast()
		a.mu.Unlock()
	})
	defer stop()
	a.mu.Lock()
	defer a.mu.Unlock()
	for a.done < n {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		a.changed.Wait()
	}
	return a.lastErr
}

// close stops the loop; an apply in progress is left to finish (or to block
// until the process exits — it is not waited for).
func (a *applier) close() { a.once.Do(func() { close(a.stop) }) }

func (a *applier) loop() {
	failures := 0
	var retry <-chan time.Time
	for {
		select {
		case <-a.stop:
			return
		case <-a.kick:
			failures = 0
		case <-retry:
		}
		retry = nil
		a.mu.Lock()
		n := a.want
		a.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), applyTimeout)
		err := a.apply(ctx)
		cancel()

		a.mu.Lock()
		a.done, a.lastErr = n, err
		a.changed.Broadcast()
		a.mu.Unlock()
		if err != nil {
			failures++
			if failures == 1 {
				a.log.Warn("tunnel routes not applied yet; retrying", "err", err)
			}
			retry = time.After(min(applyRetryEvery*time.Duration(failures), applyRetryMax))
		} else if failures > 1 {
			a.log.Info("tunnel routes applied", "after", failures)
		}
	}
}
