package pfconf

import "testing"

const (
	b1, e1 = "# >>> a >>>", "# <<< a <<<"
	b2, e2 = "# >>> b >>>", "# <<< b <<<"
)

// Two independent hooks (routing, kill switch) share pf.conf: adding or
// removing one must leave the system's rules and the other hook intact.
func TestTwoHooksCoexist(t *testing.T) {
	base := "scrub-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\nload anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\""
	c := Insert(base, b1, e1, "riftroute")
	c = Insert(c, b2, e2, "riftroute_ks")
	if Insert(c, b2, e2, "riftroute_ks") != c {
		t.Fatal("Insert must be idempotent")
	}
	if !Has(c, b1) || !Has(c, b2) {
		t.Fatalf("both hooks expected:\n%s", c)
	}
	c = Remove(c, b2, e2)
	if Has(c, b2) || !Has(c, b1) {
		t.Fatalf("removing one hook touched the other:\n%s", c)
	}
	if got := Remove(c, b1, e1); got != base+"\n" {
		t.Fatalf("system rules not restored byte-identical:\n%q", got)
	}
}
