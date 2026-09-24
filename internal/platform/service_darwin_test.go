//go:build darwin

package platform

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeLaunchd simulates launchd's asynchronous bootout: the job stays visible
// to `launchctl print` for a few polls after bootout returns.
type fakeLaunchd struct {
	calls          []string
	lingerPolls    int // polls the job survives after bootout
	loaded         bool
	bootstrapFails int // leading bootstrap attempts that fail
	t              time.Time
}

func (f *fakeLaunchd) install(t *testing.T) {
	t.Helper()
	oldCtl, oldPrint, oldNow, oldSleep := launchctl, printService, now, sleep
	t.Cleanup(func() { launchctl, printService, now, sleep = oldCtl, oldPrint, oldNow, oldSleep })
	f.t = time.Unix(0, 0)
	launchctl = func(args ...string) error {
		verb := strings.Join(args, " ")
		f.calls = append(f.calls, verb)
		switch args[0] {
		case "bootstrap":
			if f.loaded {
				return errors.New("Bootstrap failed: 5: Input/output error") // teardown still in progress
			}
			if f.bootstrapFails > 0 {
				f.bootstrapFails--
				return errors.New("Bootstrap failed: 5: Input/output error")
			}
			f.loaded = true
		}
		return nil
	}
	printService = func() (string, error) {
		f.calls = append(f.calls, "print")
		if !f.loaded {
			return "", errors.New("Could not find service")
		}
		if f.lingerPolls > 0 {
			f.lingerPolls--
			if f.lingerPolls == 0 {
				f.loaded = false // teardown finished
			}
		}
		return "state = running\n", nil
	}
	now = func() time.Time { return f.t }
	sleep = func(d time.Duration) { f.t = f.t.Add(d) }
}

func (f *fakeLaunchd) index(verb string) int {
	for i, c := range f.calls {
		if strings.HasPrefix(c, verb) {
			return i
		}
	}
	return -1
}

// The Clew race: bootout returns while the old job is still torn down. We
// must not bootstrap until launchd no longer lists the job.
func TestBootServiceWaitsForBootoutToFinish(t *testing.T) {
	f := &fakeLaunchd{loaded: true, lingerPolls: 3}
	f.install(t)
	if err := bootService(); err != nil {
		t.Fatalf("bootService: %v (calls %v)", err, f.calls)
	}
	lastPrint := -1
	for i, c := range f.calls {
		if c == "print" {
			lastPrint = i
		}
	}
	if b := f.index("bootstrap"); b < 0 || b < lastPrint {
		t.Fatalf("bootstrap ran before the old job was gone: %v", f.calls)
	}
	if f.index("load -w") >= 0 {
		t.Fatalf("legacy load must not be needed when bootstrap succeeds: %v", f.calls)
	}
	if f.index("kickstart -k") >= 0 {
		t.Fatalf("kickstart -k would kill the freshly started daemon: %v", f.calls)
	}
}

func TestBootServiceRetriesTransientBootstrapFailure(t *testing.T) {
	f := &fakeLaunchd{bootstrapFails: 2}
	f.install(t)
	if err := bootService(); err != nil {
		t.Fatalf("bootService: %v (calls %v)", err, f.calls)
	}
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, "bootstrap") {
			n++
		}
	}
	if n != 3 || !f.loaded {
		t.Fatalf("want 3 bootstrap attempts ending loaded, got %d loaded=%v: %v", n, f.loaded, f.calls)
	}
}

// If the old daemon never goes away, fail loudly rather than "install" a
// binary the old process keeps serving in front of.
func TestUnbootServiceTimesOutWhenJobNeverUnloads(t *testing.T) {
	f := &fakeLaunchd{loaded: true, lingerPolls: 1 << 30}
	f.install(t)
	err := bootService()
	if err == nil || !strings.Contains(err.Error(), "did not unload") {
		t.Fatalf("want unload timeout error, got %v", err)
	}
	if f.index("bootstrap") >= 0 {
		t.Fatalf("must not bootstrap over a job that never unloaded: %v", f.calls)
	}
}

func TestStatusReadsLaunchdPrint(t *testing.T) {
	f := &fakeLaunchd{loaded: true}
	f.install(t)
	st := launchdManager{}.Status()
	if !st.Loaded || st.Detail != "running" {
		t.Fatalf("status = %+v, want loaded+running", st)
	}
	f.loaded = false
	if st := (launchdManager{}).Status(); st.Loaded {
		t.Fatalf("unloaded job reported loaded: %+v", st)
	}
}

func TestLaunchdState(t *testing.T) {
	out := "system/com.riftroute.daemon = {\n\tactive count = 1\n\tstate = running\n\tprogram = /x\n}"
	if got := launchdState(out); got != "running" {
		t.Fatalf("launchdState = %q", got)
	}
}

// Start on a job that's already loaded must only kickstart it — a reload
// (bootout+bootstrap) kills the healthy daemon the user just asked for.
func TestStartServiceKeepsALoadedDaemon(t *testing.T) {
	f := &fakeLaunchd{loaded: true}
	f.install(t)
	if err := startService(); err != nil {
		t.Fatalf("startService: %v", err)
	}
	if f.index("bootout") >= 0 || f.index("bootstrap") >= 0 {
		t.Fatalf("reloaded a loaded job: %v", f.calls)
	}
	if f.index("kickstart system/") < 0 || f.index("kickstart -k") >= 0 {
		t.Fatalf("want a plain kickstart: %v", f.calls)
	}
}

func TestStartServiceBootstrapsAnUnloadedJob(t *testing.T) {
	f := &fakeLaunchd{}
	f.install(t)
	if err := startService(); err != nil {
		t.Fatalf("startService: %v", err)
	}
	if f.index("bootstrap") < 0 || !f.loaded {
		t.Fatalf("unloaded job not bootstrapped: %v", f.calls)
	}
}

// A socket file left by a killed daemon must not count as "came up" — only a
// listener accepting connections does.
func TestDialUntilIgnoresStaleSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "rr.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close() // leaves a stale socket file behind
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("sanity: stale socket file should exist: %v", err)
	}
	if err := dialUntil(sock, 300*time.Millisecond); err == nil {
		t.Fatal("stale socket reported as up")
	}
}

func TestDialUntilWaitsForListener(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "rr.sock")
	lnc := make(chan net.Listener, 1)
	go func() {
		time.Sleep(400 * time.Millisecond) // daemon still starting
		ln, err := net.Listen("unix", sock)
		if err != nil {
			t.Error(err)
		}
		lnc <- ln
	}()
	err := dialUntil(sock, 5*time.Second)
	if ln := <-lnc; ln != nil {
		_ = ln.Close()
	}
	if err != nil {
		t.Fatalf("listener came up but dialUntil failed: %v", err)
	}
}
