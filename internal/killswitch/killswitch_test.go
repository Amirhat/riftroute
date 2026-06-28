package killswitch

import (
	"context"
	"strings"
	"testing"
)

func TestNftRuleset(t *testing.T) {
	s := NftRuleset(Config{TunnelIfaces: []string{"wg0"}, Gateway: "192.168.1.1", LANSubnets: []string{"192.168.1.0/24"}})
	for _, want := range []string{
		"table inet riftroute_ks",
		"policy drop;",
		`oif "lo" accept`,
		`oifname "wg0" accept`,
		"ip daddr 192.168.1.1 accept",
		"ip daddr 192.168.1.0/24 accept",
		"ct state established,related accept",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("nft ruleset missing %q:\n%s", want, s)
		}
	}
}

func TestPfRuleset(t *testing.T) {
	s := PfRuleset(Config{TunnelIfaces: []string{"utun3"}, Gateway: "192.168.1.1"})
	for _, want := range []string{"pass out quick on lo0", "pass out quick on utun3", "pass out quick to 192.168.1.1", "block out all"} {
		if !strings.Contains(s, want) {
			t.Fatalf("pf ruleset missing %q:\n%s", want, s)
		}
	}
}

func TestFakeToggles(t *testing.T) {
	f := &Fake{}
	ctx := context.Background()
	if on, _ := f.Enabled(ctx); on {
		t.Fatal("should start off")
	}
	if err := f.Enable(ctx, Config{}); err != nil {
		t.Fatal(err)
	}
	if on, _ := f.Enabled(ctx); !on {
		t.Fatal("should be on after Enable")
	}
	if err := f.Disable(ctx); err != nil {
		t.Fatal(err)
	}
	if on, _ := f.Enabled(ctx); on {
		t.Fatal("should be off after Disable")
	}
}
