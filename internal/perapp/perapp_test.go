package perapp

import (
	"context"
	"strings"
	"testing"
)

func TestBuildNftMarkRuleset(t *testing.T) {
	s := BuildNftMarkRuleset([]string{"system.slice/myapp.service"}, "0x5252")
	for _, want := range []string{
		"table inet riftroute_mark",
		"type route hook output",
		`socket cgroupv2 level 2 "system.slice/myapp.service" meta mark set 0x5252`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("mark ruleset missing %q:\n%s", want, s)
		}
	}
}

func TestFakeMarker(t *testing.T) {
	f := &FakeMarker{}
	ctx := context.Background()
	if err := f.Mark(ctx, []string{"a.service", "b.service"}, "0x5252"); err != nil {
		t.Fatal(err)
	}
	if !f.Enabled || len(f.Marked) != 2 {
		t.Fatalf("fake marker state: %+v", f)
	}
	if err := f.Unmark(ctx); err != nil {
		t.Fatal(err)
	}
	if f.Enabled || f.Marked != nil {
		t.Fatalf("fake marker should be cleared: %+v", f)
	}
}
