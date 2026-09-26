package safety_test

import (
	"context"
	"testing"
	"time"
)

// The updater waits for Busy to clear: a change awaiting confirmation keeps
// the daemon busy; once it's confirmed it isn't, and the last change's time
// is reported.
func TestBusyWhileAChangeAwaitsConfirmation(t *testing.T) {
	h := newHarness(t)
	if busy, last := h.p.Busy(); busy || !last.IsZero() {
		t.Fatalf("fresh protocol: busy=%v last=%v", busy, last)
	}
	res, err := h.p.Apply(context.Background(), desired("1.1.1.0/24"), nil, opts(true))
	if err != nil {
		t.Fatal(err)
	}
	if busy, last := h.p.Busy(); !busy || last.IsZero() {
		t.Fatalf("awaiting confirmation: busy=%v last=%v", busy, last)
	}
	if _, err := h.p.Confirm(res.TxID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if busy, _ := h.p.Busy(); !busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("still busy after the change was confirmed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
