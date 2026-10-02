package telemetry

import (
	"os"
	"path/filepath"
	"testing"
)

// Counts survive a restart, go away once a report carried them (but not what
// was counted meanwhile), and aren't kept at all with telemetry off.
func TestCountersLifecycle(t *testing.T) {
	dir := t.TempDir()
	c := OpenCounters(dir, true)
	c.Inc(KeyStarts)
	c.Add(TunnelKey("ikev2", TunnelConnected), 2)
	c.Inc(FailureKey("ikev2", "cert"))
	c.Inc(FailureKey("ikev2", "some new code")) // → other
	c.Inc("tunnel.office.connected")            // a name: refused
	c.Inc("hostname")                           // not in the schema
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	c2 := OpenCounters(dir, true)
	snap := c2.Snapshot()
	want := map[string]int{KeyStarts: 1, "tunnel.ikev2.connected": 2, "tunnel.ikev2.failed.cert": 1, "tunnel.ikev2.failed.other": 1}
	if len(snap) != len(want) {
		t.Fatalf("snapshot %v", snap)
	}
	for k, n := range want {
		if snap[k] != n {
			t.Fatalf("snapshot %v", snap)
		}
	}
	c2.Inc(KeyStarts) // counted after the snapshot
	if err := c2.Settle("r1", snap); err != nil {
		t.Fatal(err)
	}
	if got := c2.Snapshot(); len(got) != 1 || got[KeyStarts] != 1 {
		t.Fatalf("after settling %v", got)
	}
	// Settled once, even across a restart (a crash before the sender's
	// state recorded it).
	if err := OpenCounters(dir, true).Settle("r1", snap); err != nil {
		t.Fatal(err)
	}
	if got := OpenCounters(dir, true).Snapshot(); len(got) != 1 || got[KeyStarts] != 1 {
		t.Fatalf("settled twice: %v", got)
	}

	// The boot guard, before the daemon opens them.
	_ = c2.Flush()
	if err := AddToFile(dir, KeyRolledBackHlth, 1); err != nil {
		t.Fatal(err)
	}
	if got := OpenCounters(dir, true).Snapshot(); got[KeyRolledBackHlth] != 1 || got[KeyStarts] != 1 {
		t.Fatalf("after AddToFile %v", got)
	}

	// Off: forgotten, the file gone, nothing counted — not even by the boot guard.
	off := OpenCounters(dir, false)
	off.Inc(KeyStarts)
	if _, err := os.Stat(filepath.Join(dir, "telemetry-counters.json")); !os.IsNotExist(err) {
		t.Fatal("counters file kept with telemetry off")
	}
	if err := AddToFile(dir, KeyInstalled, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "telemetry-counters.json")); !os.IsNotExist(err) {
		t.Fatal("AddToFile counted with telemetry off")
	}
	if len(off.Snapshot()) != 0 {
		t.Fatal("counted while off")
	}
	// Turned on again: counting starts afresh.
	off.SetOn(true)
	off.Inc(KeyStarts)
	if got := off.Snapshot(); got[KeyStarts] != 1 || len(got) != 1 {
		t.Fatalf("on again %v", got)
	}
	var nilc *Counters
	nilc.Inc(KeyStarts) // no panic
}

func TestEveryCounterKeyFitsTheReport(t *testing.T) {
	for _, k := range []string{KeyStarts, KeyUnclean, KeyPanics, KeyInstalled, KeyRolledBackHlth, KeyRolledBackUser,
		KeySkippedBroken, KeyHelpersRepaired, KeyCheckFailed, KeyDNSFailures} {
		if !ValidKey(k) {
			t.Errorf("%s", k)
		}
	}
	for _, typ := range TunnelTypes {
		for _, ev := range []string{TunnelConnected, TunnelDrop, TunnelGaveUp} {
			if !ValidKey(TunnelKey(typ, ev)) {
				t.Errorf("%s %s", typ, ev)
			}
		}
		for _, code := range FailureCodes {
			if !ValidKey(FailureKey(typ, code)) {
				t.Errorf("%s %s", typ, code)
			}
		}
	}
}

// A write racing telemetry being turned off can't bring the file back.
func TestCountersDontWriteWhileOff(t *testing.T) {
	dir := t.TempDir()
	c := OpenCounters(dir, true)
	c.Inc(KeyStarts)
	c.SetOn(false)
	c.mu.Lock()
	c.counts[KeyStarts], c.dirty = 5, true // what a Flush that snapshotted before Discard would write
	c.mu.Unlock()
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "telemetry-counters.json")); !os.IsNotExist(err) {
		t.Fatal("the counters file came back while off")
	}
}
