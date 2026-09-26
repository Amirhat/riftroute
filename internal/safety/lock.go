package safety

import "context"

// applyLock serializes applies. Unlike a sync.Mutex, a waiter can give up: an
// apply whose caller stopped waiting — its deadline passed while another
// change held the lock — must not take the lock afterwards and change the
// routing table for nobody.
type applyLock chan struct{}

func newApplyLock() applyLock { return make(applyLock, 1) }

// Lock takes the lock, however long that takes.
func (l applyLock) Lock() { l <- struct{}{} }

// LockCtx takes the lock unless ctx ends first (or already has). It never
// holds the lock once it has returned an error.
func (l applyLock) LockCtx(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case l <- struct{}{}:
		// Both may have been ready at once; a caller that is gone doesn't
		// get a change made on its behalf.
		if err := ctx.Err(); err != nil {
			l.Unlock()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TryLock takes the lock if it is free.
func (l applyLock) TryLock() bool {
	select {
	case l <- struct{}{}:
		return true
	default:
		return false
	}
}

// Unlock releases the lock.
func (l applyLock) Unlock() { <-l }
