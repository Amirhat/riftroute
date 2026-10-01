package safety_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// lastAudit returns the newest audit event with action.
func (h *harness) lastAudit(t *testing.T, action string) domain.AuditEvent {
	t.Helper()
	evs, err := h.st.ListAudit(time.Time{}, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs { // newest first
		if e.Action == action {
			return e
		}
	}
	t.Fatalf("no %q audit event", action)
	return domain.AuditEvent{}
}

// The history says why a change was rolled back: the connection lost, not
// kept in time, or asked for.
func TestRollbackSaysWhy(t *testing.T) {
	for _, c := range []struct {
		name string
		run  func(h *harness, tx string)
		want string
	}{
		{"watchdog", func(h *harness, _ string) {
			h.prober.SetReachable("192.168.1.1", false)
			h.clock.Advance(time.Second)
		}, "the connection was lost"},
		{"unconfirmed", func(h *harness, _ string) { h.clock.Advance(15 * time.Second) }, "not kept in time"},
		{"requested", func(h *harness, tx string) { _, _ = h.p.Rollback(tx) }, "reverted on request"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			res, err := h.p.Apply(context.Background(), desired("9.9.9.0/24"), nil, opts(c.name != "watchdog"))
			if err != nil || res.Status != domain.TxPending {
				t.Fatalf("apply: %s %v", res.Status, err)
			}
			c.run(h, res.TxID)
			if got, _ := h.p.Wait(res.TxID); got != domain.TxRolledBack {
				t.Fatalf("result = %s", got)
			}
			if e := h.lastAudit(t, "rollback"); !strings.Contains(e.Reason, c.want) {
				t.Errorf("reason = %q, want %q", e.Reason, c.want)
			}
		})
	}
}

// An applied change's history entry says how long it took, by part.
func TestAppliedChangeRecordsItsTiming(t *testing.T) {
	h := newHarness(t)
	res, err := h.p.Apply(context.Background(), desired("9.9.9.0/24", "9.9.10.0/24"), nil, opts(true))
	if err != nil || res.Status != domain.TxPending {
		t.Fatalf("apply: %s %v", res.Status, err)
	}
	e := h.lastAudit(t, "apply")
	if e.Result != "applied" || e.Timing == nil {
		t.Fatalf("applied event = %+v", e)
	}
	tm := e.Timing
	if tm.TotalMS < 0 || tm.WaitMS+tm.BuildMS+tm.CheckMS+tm.ExecMS != tm.TotalMS {
		t.Errorf("the parts don't add up: %+v", tm)
	}
}
