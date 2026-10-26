package tunneldns

import (
	"fmt"
	"net/netip"
	"testing"
)

func TestClean(t *testing.T) {
	var in []netip.Addr
	for _, s := range []string{"10.8.0.1", "127.0.0.1", "0.0.0.0", "224.0.0.251", "fe80::1", "10.8.0.1", "::ffff:10.8.0.2",
		"1.1.1.1", "1.0.0.1", "9.9.9.9", "8.8.8.8", "fd00::53"} {
		in = append(in, netip.MustParseAddr(s))
	}
	if got := fmt.Sprint(Clean(in)); got != "[10.8.0.1 10.8.0.2 1.1.1.1 1.0.0.1 fd00::53]" {
		t.Fatalf("Clean = %s", got)
	}
}
