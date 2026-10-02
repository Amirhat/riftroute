package updater

import (
	"testing"

	"github.com/Amirhat/riftroute/internal/telemetry"
)

// A rollback is counted for the anonymous report — by the boot guard, before
// the database opens, straight into the counters file — but only while
// telemetry is on (the file exists).
func TestRollbacksAreCounted(t *testing.T) {
	h := installed(t)
	telemetry.OpenCounters(h.env.StateDir, true) // telemetry on
	for i := 0; i <= maxBoots; i++ {             // three failed starts, then the rollback
		_, _ = BootGuard(guardEnv(h, "0.2.7"))
	}
	if got := telemetry.OpenCounters(h.env.StateDir, true).Snapshot(); got[telemetry.KeyRolledBackHlth] != 1 {
		t.Fatalf("counted %v", got)
	}

	off := installed(t)
	telemetry.OpenCounters(off.env.StateDir, false) // telemetry off
	for i := 0; i <= maxBoots; i++ {
		_, _ = BootGuard(guardEnv(off, "0.2.7"))
	}
	if got := telemetry.OpenCounters(off.env.StateDir, true).Snapshot(); len(got) != 0 {
		t.Fatalf("counted with telemetry off: %v", got)
	}
}

// The updater's own outcomes go through Env.Count.
func TestUpdaterCounts(t *testing.T) {
	f := newFakeRelease(t, "0.3.0", fakeDaemon("0.3.0"))
	f.tgz = macReleaseWith(t, "0.3.0", fakeOpenVPN("shipped"), fakeCharonCmd("shipped"))
	h := newHarness(t, f, "0.3.0")
	var keys []string
	h.u.env.Count = func(k string) { keys = append(keys, k) }
	withOpenVPN(t, h, fakeOpenVPN("mine"))
	withCharonCmd(t, h, nil)
	h.check()
	if len(keys) != 1 || keys[0] != telemetry.KeyHelpersRepaired {
		t.Fatalf("counted %v", keys)
	}
}
