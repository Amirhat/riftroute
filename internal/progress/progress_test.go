package progress

import (
	"context"
	"sync"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

// A change's steps reach the reporter in its context: each new step, and a
// counted step's last item, always; the counts in between spaced out. With
// no reporter, reporting does nothing.
func TestReport(t *testing.T) {
	Report(context.Background(), domain.StepChecking, 0, 0) // no reporter: nothing to do

	var mu sync.Mutex
	var got []domain.ApplyProgress
	ctx := With(context.Background(), "p1", func(p domain.ApplyProgress) {
		mu.Lock()
		got = append(got, p)
		mu.Unlock()
	})
	Report(ctx, domain.StepWaiting, 0, 0)
	c := Count(ctx, domain.StepApplying, 500)
	for range 500 {
		c.Add()
	}
	Report(ctx, domain.StepChecking, 0, 0)

	mu.Lock()
	defer mu.Unlock()
	if len(got) < 4 || len(got) > 20 {
		t.Fatalf("%d updates: %+v", len(got), got)
	}
	if got[0] != (domain.ApplyProgress{ID: "p1", Step: domain.StepWaiting}) ||
		got[1] != (domain.ApplyProgress{ID: "p1", Step: domain.StepApplying, Total: 500}) {
		t.Errorf("first updates = %+v", got[:2])
	}
	if last := got[len(got)-2]; last.Step != domain.StepApplying || last.Done != 500 {
		t.Errorf("the step's last item wasn't reported: %+v", last)
	}
	if got[len(got)-1].Step != domain.StepChecking {
		t.Errorf("the next step wasn't reported: %+v", got[len(got)-1])
	}
}

func TestValidID(t *testing.T) {
	for id, want := range map[string]bool{"a-1_B": true, "": false, "a b": false, "a\nb": false, string(make([]byte, 65)): false} {
		if ValidID(id) != want {
			t.Errorf("ValidID(%q) = %v", id, !want)
		}
	}
}
