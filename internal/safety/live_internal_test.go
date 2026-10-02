package safety

import (
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// Sightings within liveGap are one (a burst of applies sees one removal), and
// only liveStrikes within liveWindow hold a route: removals spread out (a
// network that drops it now and then) are put back each time.
func TestLiveRepairCounting(t *testing.T) {
	m := []domain.ManagedRoute{{Route: domain.Route{DstCIDR: "9.9.9.0/24", Gateway: "192.168.1.1", Iface: "en0", Family: domain.FamilyV4}}}
	t0 := time.Unix(0, 0)
	var l liveRepair

	for _, d := range []time.Duration{0, 5 * time.Second, 10 * time.Second, 19 * time.Second} {
		if held := l.note(m, t0.Add(d)); len(held) != 0 {
			t.Fatalf("a burst held it at +%s", d)
		}
	}
	if held := l.note(m, t0.Add(40*time.Second)); len(held) != 0 {
		t.Fatal("held on the second sighting")
	}
	if held := l.note(m, t0.Add(80*time.Second)); len(held) != 1 {
		t.Fatal("not held on the third sighting within the window")
	}
	if len(l.held(t0.Add(81*time.Second))) != 1 || len(l.list(t0.Add(81*time.Second))) != 1 {
		t.Fatal("not listed as held")
	}
	if len(l.held(t0.Add(80*time.Second+liveHold))) != 0 {
		t.Fatal("still held after liveHold")
	}

	var spread liveRepair
	for i := 0; i < 6; i++ {
		if held := spread.note(m, t0.Add(time.Duration(i)*6*time.Minute)); len(held) != 0 {
			t.Fatalf("removals 6 minutes apart held it (sighting %d)", i+1)
		}
	}
}
