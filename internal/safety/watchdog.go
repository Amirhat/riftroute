package safety

import (
	"context"
	"net/netip"
	"time"
)

// CanaryAnchor is the internet canary the daemon's applies probe beside the
// physical gateway.
const CanaryAnchor = "1.1.1.1"

// DefaultAnchors are the connectivity anchors of a daemon or UI apply: the
// physical gateway (when resolved) and the canary. Tunnel routes are kept
// from capturing them (core), so what the watchdog probes stays off tunnels.
func DefaultAnchors(physGW netip.Addr) []string {
	anchors := []string{}
	if physGW.IsValid() {
		anchors = append(anchors, physGW.String())
	}
	return append(anchors, CanaryAnchor)
}

// Watchdog is the connectivity deadman switch (spec §2.1/§2.5). Armed before a
// change with a precomputed recovery action, it probes the anchors ~once per
// interval; if ALL anchors are unreachable for K consecutive probes it fires the
// recovery (rollback) immediately. Connectivity is "lost" only when every anchor
// fails, so a single down canary does not trigger a revert.
type Watchdog struct {
	clock    Clock
	prober   Prober
	anchors  []string
	k        int
	interval time.Duration
	onFire   func()

	// probed, if set, emits the consecutive-failure count after each probe so
	// tests can drive the fake clock deterministically.
	probed chan int
}

// NewWatchdog builds a watchdog. k<1 is treated as 1.
func NewWatchdog(clock Clock, prober Prober, anchors []string, k int, interval time.Duration, onFire func()) *Watchdog {
	if k < 1 {
		k = 1
	}
	return &Watchdog{clock: clock, prober: prober, anchors: anchors, k: k, interval: interval, onFire: onFire}
}

// Run probes until ctx is canceled or it fires. first is the initial timer
// channel; creating it synchronously (before Run is scheduled) guarantees the
// timer is registered before the caller advances a fake clock.
func (w *Watchdog) Run(ctx context.Context, first <-chan time.Time) {
	consecutive := 0
	tick := first
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			if w.allUnreachable(ctx) {
				consecutive++
			} else {
				consecutive = 0
			}
			// Register the next tick BEFORE signaling so a test that waits on
			// `probed` can advance the clock without racing re-registration.
			tick = w.clock.After(w.interval)
			if w.probed != nil {
				select {
				case w.probed <- consecutive:
				default:
				}
			}
			if consecutive >= w.k {
				w.onFire()
				return
			}
		}
	}
}

func (w *Watchdog) allUnreachable(ctx context.Context) bool {
	if len(w.anchors) == 0 {
		return false // nothing to watch → never fire
	}
	for _, a := range w.anchors {
		if w.prober.Probe(ctx, a) {
			return false
		}
	}
	return true
}
