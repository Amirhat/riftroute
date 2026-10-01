package safety

import (
	"testing"
	"time"
)

// The parts of a change's timing always add up to its total, even when each
// is a fraction of a millisecond (CI saw 4 ms of parts in a 5 ms total).
func TestTimingPartsAddUp(t *testing.T) {
	t0 := time.Now()
	at := func(us int) time.Time { return t0.Add(time.Duration(us) * time.Microsecond) }
	tm := &timing{start: t0, locked: at(600), built: at(1200), vetted: at(1800), done: at(2400)}
	s := tm.summary()
	if s.TotalMS != 2 || s.WaitMS+s.BuildMS+s.CheckMS+s.ExecMS != s.TotalMS {
		t.Fatalf("summary = %+v", s)
	}
	// Parts that weren't marked took no time.
	s = (&timing{start: t0, done: at(3000)}).summary()
	if s.TotalMS != 3 || s.ExecMS != 3 || s.WaitMS+s.BuildMS+s.CheckMS != 0 {
		t.Fatalf("unmarked parts: %+v", s)
	}
}
