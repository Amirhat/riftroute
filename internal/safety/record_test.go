package safety_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/safety"
)

// recorder collects the records (Options.OnCommit) changes make, in order.
type recorder struct {
	mu  sync.Mutex
	got []string
}

func (r *recorder) as(name string) func() {
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.got = append(r.got, name)
	}
}

func (r *recorder) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.got, ",")
}

func recording(o safety.Options, fn func()) safety.Options {
	o.OnCommit = fn
	return o
}

// onProbation applies cidrs guarded, recording name when it commits, and
// returns the transaction on probation.
func (h *harness) onProbation(t *testing.T, rec *recorder, name string, cidrs ...string) string {
	t.Helper()
	res, err := h.p.Apply(context.Background(), desired(cidrs...), nil, recording(opts(false), rec.as(name)))
	if err != nil || res.Status != domain.TxPending {
		t.Fatalf("apply: %v, %s", err, res.Status)
	}
	return res.TxID
}

func (h *harness) commitsAfterItsWindow(t *testing.T, txID string) {
	t.Helper()
	h.clock.Advance(30 * time.Second)
	if got, _ := h.p.Wait(txID); got != domain.TxCommitted {
		t.Fatalf("want committed, got %s", got)
	}
}

// A change that changes nothing while another is on probation takes that
// one's place: its record is newer, and lands if that one commits.
func TestUnchangedBesideAPendingChangeRecordsInItsPlace(t *testing.T) {
	h := newHarness(t)
	rec := &recorder{}
	tx := h.onProbation(t, rec, "A", "9.9.9.0/24")
	res, err := h.p.Apply(context.Background(), desired("9.9.9.0/24"), nil, recording(opts(false), rec.as("B")))
	if err != nil || res.Status != domain.TxCommitted || len(res.Plan.Ops) != 0 {
		t.Fatalf("no-op apply: %v, %s, %d op(s)", err, res.Status, len(res.Plan.Ops))
	}
	if rec.String() != "" {
		t.Fatalf("recorded %q before the change on probation settled", rec)
	}
	h.commitsAfterItsWindow(t, tx)
	if rec.String() != "B" {
		t.Fatalf("records = %q, want the newer one in the place of the pending one's", rec)
	}
}

// If the change on probation rolls back, neither record lands: the routes
// are back to what the record before them describes.
func TestUnchangedBesideAChangeThatRollsBackRecordsNothing(t *testing.T) {
	h := newHarness(t)
	rec := &recorder{}
	tx := h.onProbation(t, rec, "A", "9.9.9.0/24")
	if _, err := h.p.Apply(context.Background(), desired("9.9.9.0/24"), nil, recording(opts(false), rec.as("B"))); err != nil {
		t.Fatal(err)
	}
	h.fireGuard(t, tx)
	if rec.String() != "" {
		t.Fatalf("records = %q after a rollback, want none", rec)
	}
}

// A set built on a record (a tunnel apply) that changes nothing while
// another change is on probation records nothing: it was built from the
// record that change is about to replace.
func TestUnchangedBuiltOnARecordBesideAPendingChangeRecordsNothing(t *testing.T) {
	h := newHarness(t)
	rec := &recorder{}
	tx := h.onProbation(t, rec, "A", "9.9.9.0/24")
	o := opts(false)
	o.Unguarded, o.BuiltOnRecord = true, true
	res, err := h.p.ApplyBuilt(context.Background(), func(_ context.Context, owned []domain.ManagedRoute, o *safety.Options) ([]domain.ManagedRoute, []domain.ManagedRule, error) {
		o.OnCommit = rec.as("U")
		return owned, nil, nil
	}, o)
	if err != nil || res.Status != domain.TxCommitted {
		t.Fatalf("no-op apply: %v, %s", err, res.Status)
	}
	h.commitsAfterItsWindow(t, tx)
	if rec.String() != "A" {
		t.Fatalf("records = %q, want only the pending change's", rec)
	}
}

// A set built on a record while another change is on probation, that goes
// ahead, is built again once that change has settled — from its record.
func TestBuiltOnARecordBesideAPendingChangeIsBuiltAgainFromItsRecord(t *testing.T) {
	h := newHarness(t)
	rec := &recorder{}
	tx := h.onProbation(t, rec, "A", "9.9.9.0/24")
	o := opts(false)
	o.Unguarded, o.BuiltOnRecord = true, true
	var builtOn []string
	res, err := h.p.ApplyBuilt(context.Background(), func(_ context.Context, owned []domain.ManagedRoute, o *safety.Options) ([]domain.ManagedRoute, []domain.ManagedRule, error) {
		builtOn = append(builtOn, rec.String())
		o.OnCommit = rec.as("U")
		return append(owned, desired("8.8.8.0/24")...), nil, nil
	}, o)
	if err != nil || res.Status != domain.TxCommitted {
		t.Fatalf("apply: %v, %s", err, res.Status)
	}
	if got, _ := h.p.Wait(tx); got != domain.TxCommitted {
		t.Fatalf("the pending change: %s, want settled by the apply", got)
	}
	if strings.Join(builtOn, "|") != "|A" {
		t.Fatalf("built on %q, want built again on the settled change's record", builtOn)
	}
	if rec.String() != "A,U" {
		t.Fatalf("records = %q", rec)
	}
	if h.prov.CountManaged() != 2 {
		t.Fatalf("%d managed route(s), want 2", h.prov.CountManaged())
	}
}

// A set built from scratch is built once: what the change on probation
// records doesn't change it.
func TestBuiltFromScratchBesideAPendingChangeIsBuiltOnce(t *testing.T) {
	h := newHarness(t)
	rec := &recorder{}
	tx := h.onProbation(t, rec, "A", "9.9.9.0/24")
	builds := 0
	res, err := h.p.ApplyBuilt(context.Background(), func(_ context.Context, _ []domain.ManagedRoute, o *safety.Options) ([]domain.ManagedRoute, []domain.ManagedRule, error) {
		builds++
		o.OnCommit = rec.as("B")
		return desired("9.9.9.0/24", "8.8.8.0/24"), nil, nil
	}, opts(false))
	if err != nil || res.Status != domain.TxPending || builds != 1 {
		t.Fatalf("apply: %v, %s, %d build(s)", err, res.Status, builds)
	}
	if got, _ := h.p.Wait(tx); got != domain.TxCommitted {
		t.Fatalf("the pending change: %s", got)
	}
	h.commitsAfterItsWindow(t, res.TxID)
	if rec.String() != "A,B" {
		t.Fatalf("records = %q", rec)
	}
}

// A record that panics is logged; the change it records still stands, and
// the protocol goes on.
func TestAPanickingRecordLeavesTheChangeStanding(t *testing.T) {
	h := newHarness(t)
	boom := func() { panic("boom") }
	res, err := h.p.Apply(context.Background(), desired("9.9.9.0/24"), nil, recording(opts(false), boom))
	if err != nil {
		t.Fatal(err)
	}
	h.commitsAfterItsWindow(t, res.TxID)
	un := opts(false)
	un.Unguarded = true
	res, err = h.p.Apply(context.Background(), desired("9.9.9.0/24", "8.8.8.0/24"), nil, recording(un, boom))
	if err != nil || res.Status != domain.TxCommitted {
		t.Fatalf("unguarded apply: %v, %s", err, res.Status)
	}
	if n := h.prov.CountManaged(); n != 2 {
		t.Fatalf("%d managed route(s), want both changes standing", n)
	}
	if _, err := h.p.Apply(context.Background(), desired("9.9.9.0/24"), nil, un); err != nil {
		t.Fatalf("the next apply: %v", err)
	}
}

// A panic's Flushing step comes after the changes it settles have recorded
// theirs, and before the flush: nothing they record survives it.
func TestPanicFlushingComesAfterThePendingRecords(t *testing.T) {
	h := newHarness(t)
	rec := &recorder{}
	h.onProbation(t, rec, "A", "9.9.9.0/24")
	err := h.p.PanicWith(context.Background(), domain.ActorUI, safety.PanicSteps{
		Before: func(context.Context) { rec.as("before")() },
		Flushing: func() {
			if h.prov.CountManaged() == 0 {
				t.Error("flushed before the Flushing step")
			}
			rec.as("flushing")()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.String() != "before,A,flushing" {
		t.Fatalf("order = %q", rec)
	}
	if n := h.prov.CountManaged(); n != 0 {
		t.Fatalf("%d managed route(s) after the panic", n)
	}
}
