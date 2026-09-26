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

// TryQuiesce refuses while a change awaits confirmation, and once taken it
// blocks new changes until released.
func TestTryQuiesceHoldsOffNewChanges(t *testing.T) {
	h := newHarness(t)
	res, err := h.p.Apply(context.Background(), desired("1.1.1.0/24"), nil, opts(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, why := h.p.TryQuiesce(0); ok || why == "" {
		t.Fatal("quiesced while a change awaits confirmation")
	}
	if _, err := h.p.Confirm(res.TxID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	var release func()
	for {
		var ok bool
		if release, ok, _ = h.p.TryQuiesce(0); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("never quiet after confirming")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok, _ := h.p.TryQuiesce(time.Hour); ok {
		t.Fatal("a recent change should keep it from being quiet for an hour")
	}
	done := make(chan struct{})
	go func() {
		_, _ = h.p.Apply(context.Background(), desired("2.2.2.0/24"), nil, opts(false))
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("a change went through while quiesced")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	release() // idempotent
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the change never ran after release")
	}
}
