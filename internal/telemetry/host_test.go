package telemetry

import (
	"runtime"
	"testing"
)

func TestOSRelease(t *testing.T) {
	for _, c := range []struct {
		in    string
		id    string
		major int
	}{
		{"NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n", "ubuntu", 24},
		{"ID=debian\nVERSION_ID=\"12\"\n", "debian", 12},
		{"ID=arch\nBUILD_ID=rolling\n", "arch", 0},
		{"ID='opensuse-tumbleweed'\nVERSION_ID=\"20261001\"\n", "opensuse-tumbleweed", 0}, // a date, not a version
		{"", "", 0},
	} {
		id, major := osRelease([]byte(c.in))
		if id != c.id || major != c.major {
			t.Errorf("%q: %q %d, want %q %d", c.in, id, major, c.id, c.major)
		}
	}
}

func TestNewApp(t *testing.T) {
	for v, want := range map[string]string{"0.7.0": "0.7.0", "v0.7.0": "0.7.0", "dev": "dev", "0.6.1-3-gabc1234": "dev", "": "dev"} {
		if got := releaseVersion(v); got != want {
			t.Errorf("%q: %q, want %q", v, got, want)
		}
	}
	a := NewApp("0.7.0", "nightly", true)
	if a.Channel != "other" || a.Version != "0.7.0" || !a.Service {
		t.Fatalf("%+v", a)
	}
	r := &Report{Schema: Schema, Install: "0123456789abcdef0123456789abcdef", Level: "basic", Day: "2026-10-02", App: a}
	if err := r.Validate(); err != nil {
		t.Fatalf("this machine's app doesn't validate: %v (%+v)", err, a)
	}
	if runtime.GOOS == "darwin" && a.OSMajor < 11 {
		t.Errorf("macOS major %d", a.OSMajor)
	}
}
