package main

import (
	"reflect"
	"testing"
)

// The self-test runs with the service's own arguments — minus its database
// and any -selftest — pointed at the copy.
func TestSelfTestArgs(t *testing.T) {
	cases := map[string]struct{ in, want []string }{
		"launchd plist": {
			in:   []string{"-provider", "auto", "-socket", "/var/run/riftroute.sock", "-allow-uid", "501"},
			want: []string{"-selftest", "-db", "/tmp/c.db", "-provider", "auto", "-socket", "/var/run/riftroute.sock", "-allow-uid", "501"},
		},
		"db replaced (both forms)": {
			in:   []string{"-db", "/live.db", "--db=/other.db", "-provider=auto"},
			want: []string{"-selftest", "-db", "/tmp/c.db", "-provider=auto"},
		},
		"no double selftest": {
			in:   []string{"-selftest", "-provider", "auto"},
			want: []string{"-selftest", "-db", "/tmp/c.db", "-provider", "auto"},
		},
	}
	for name, c := range cases {
		if got := selfTestArgs(c.in, "/tmp/c.db"); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}
