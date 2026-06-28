// Package e2e is a real end-to-end test: it builds the actual riftrouted +
// riftroute binaries, starts the daemon on a temp Unix socket with the fake
// provider, and drives the full lifecycle over the real socket — closing the
// integration seam (daemon ↔ UDS ↔ apiclient ↔ CLI) that unit tests don't
// cover. It is host-safe (fake provider: no root, no real routes) and offline:
// it asserts on immediate post-apply effects and confirms/rolls back/panics
// within milliseconds, so it never depends on the watchdog's timing or on
// anchor reachability.
//
// Excluded from the core `go test ./internal/... ./cmd/...` run by path; invoked
// explicitly via `make test-e2e` and a dedicated CI job.
package e2e

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/apiclient"
	"github.com/Amirhat/riftroute/internal/config"
	"github.com/Amirhat/riftroute/internal/domain"
)

var daemonBin, cliBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "rr-e2e-bin")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	daemonBin = filepath.Join(dir, "riftrouted")
	cliBin = filepath.Join(dir, "riftroute")
	for _, b := range []struct{ out, pkg string }{
		{daemonBin, "../../cmd/riftrouted"},
		{cliBin, "../../cmd/riftroute"},
	} {
		cmd := exec.Command("go", "build", "-o", b.out, b.pkg)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, berr := cmd.CombinedOutput(); berr != nil {
			fmt.Fprintf(os.Stderr, "build %s: %v\n%s", b.pkg, berr, out)
			os.Exit(1)
		}
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

type daemon struct {
	sock string
	cl   *apiclient.Client
}

// start boots a real riftrouted (fake provider) on a temp socket and waits until
// it answers, killing it at test end.
func start(t *testing.T) *daemon {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "d.sock")
	db := filepath.Join(dir, "d.db")
	cmd := exec.Command(daemonBin,
		"-socket", sock, "-db", db, "-provider", "fake",
		"-log", "error", "-push-interval", "0", "-auto-apply=false")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	cl := apiclient.New(sock)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		_, err := cl.Ping(ctx)
		cancel()
		if err == nil {
			return &daemon{sock: sock, cl: cl}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("daemon did not become ready in time")
	return nil
}

const sampleConfig = `version: 1
settings:
  split_dns:
    - domain: corp.example.com
      resolver: 10.0.0.53
lists:
  - name: corp-nets
    static: [10.0.0.0/8, 192.168.50.0/24]
profiles:
  - name: work
    enabled: true
    mode: exclude
    lists: [corp-nets]
    rules:
      - { type: cidr, value: 172.16.0.0/12 }
`

func ctx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 10*time.Second)
}

func TestE2E_StatusAndState(t *testing.T) {
	d := start(t)
	c, cancel := ctx(t)
	defer cancel()

	ver, err := d.cl.Ping(c)
	if err != nil || ver == "" {
		t.Fatalf("ping: ver=%q err=%v", ver, err)
	}
	st, err := d.cl.State(c)
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if st.Health.Daemon != domain.DaemonOK {
		t.Fatalf("daemon not ok: %+v", st.Health)
	}
	if st.Health.Provider != "fake" {
		t.Fatalf("provider = %q, want fake", st.Health.Provider)
	}
}

func TestE2E_ConfigDryRunApplyConfirm(t *testing.T) {
	d := start(t)
	c, cancel := ctx(t)
	defer cancel()

	// Dry-run: produces a plan, no errors, changes nothing.
	dry, err := d.cl.ApplyConfig(c, []byte(sampleConfig), "yaml", true, false)
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if dry.Plan == nil {
		t.Fatalf("dry-run produced no plan: %+v", dry)
	}
	if hasErrors(dry.Issues) {
		t.Fatalf("dry-run reported config errors: %+v", dry.Issues)
	}
	if pre, _ := d.cl.State(c); pre.ManagedRouteCount != 0 {
		t.Fatalf("dry-run mutated state: %d routes", pre.ManagedRouteCount)
	}

	// Interactive apply → routes installed pending confirm.
	res, err := d.cl.ApplyConfig(c, []byte(sampleConfig), "yaml", false, false)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Result == nil || !res.Result.NeedsConfirm || res.Result.TxID == "" {
		t.Fatalf("interactive apply should need confirm: %+v", res.Result)
	}
	st, _ := d.cl.State(c)
	if st.ManagedRouteCount == 0 {
		t.Fatal("routes should be installed pending confirm")
	}

	// Confirm keeps the change (explicit; independent of the watchdog).
	tx, err := d.cl.Confirm(c, res.Result.TxID)
	if err != nil || tx != domain.TxCommitted {
		t.Fatalf("confirm: tx=%s err=%v", tx, err)
	}
	st, _ = d.cl.State(c)
	if st.ManagedRouteCount == 0 {
		t.Fatal("committed routes vanished")
	}
	if st.Drift.Pending {
		t.Fatalf("drift should be clear after confirm: %+v", st.Drift)
	}

	// Panic flushes everything (idempotent).
	if err := d.cl.Panic(c); err != nil {
		t.Fatalf("panic: %v", err)
	}
	st, _ = d.cl.State(c)
	if st.ManagedRouteCount != 0 {
		t.Fatalf("panic left %d routes", st.ManagedRouteCount)
	}
	if err := d.cl.Panic(c); err != nil {
		t.Fatalf("panic not idempotent: %v", err)
	}
}

func TestE2E_ApplyRollback(t *testing.T) {
	d := start(t)
	c, cancel := ctx(t)
	defer cancel()

	res, err := d.cl.ApplyConfig(c, []byte(sampleConfig), "yaml", false, false)
	if err != nil || res.Result == nil || !res.Result.NeedsConfirm {
		t.Fatalf("apply should need confirm: %+v err=%v", res.Result, err)
	}
	if st, _ := d.cl.State(c); st.ManagedRouteCount == 0 {
		t.Fatal("routes should be installed before rollback")
	}
	tx, err := d.cl.Rollback(c, res.Result.TxID)
	if err != nil || tx != domain.TxRolledBack {
		t.Fatalf("rollback: tx=%s err=%v", tx, err)
	}
	if st, _ := d.cl.State(c); st.ManagedRouteCount != 0 {
		t.Fatalf("rollback left routes: %+v", st)
	}
}

func TestE2E_KillSwitch(t *testing.T) {
	d := start(t)
	c, cancel := ctx(t)
	defer cancel()

	on, err := d.cl.SetKillSwitch(c, true)
	if err != nil || !on {
		t.Fatalf("enable kill switch: on=%v err=%v", on, err)
	}
	if st, _ := d.cl.State(c); !st.KillSwitch {
		t.Fatal("state should report kill switch armed")
	}
	off, err := d.cl.SetKillSwitch(c, false)
	if err != nil || off {
		t.Fatalf("disable kill switch: off=%v err=%v", off, err)
	}
	if st, _ := d.cl.State(c); st.KillSwitch {
		t.Fatal("state should report kill switch disarmed")
	}
}

func TestE2E_FlowsAndDoctor(t *testing.T) {
	d := start(t)
	c, cancel := ctx(t)
	defer cancel()

	if _, err := d.cl.Flows(c); err != nil {
		t.Fatalf("flows: %v", err)
	}
	rep, err := d.cl.Doctor(c)
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if len(rep.Checks) == 0 {
		t.Fatal("doctor returned no checks")
	}
}

func TestE2E_CLIExitCodes(t *testing.T) {
	d := start(t)
	cfg := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(cfg, []byte(sampleConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"version", []string{"--socket", d.sock, "version"}, 0},
		{"status", []string{"--socket", d.sock, "status"}, 0},
		{"doctor-healthy", []string{"--socket", d.sock, "doctor"}, 0},
		{"flows", []string{"--socket", d.sock, "flows"}, 0},
		{"apply-dry-run", []string{"--socket", d.sock, "apply", cfg, "--dry-run"}, 0},
		{"unreachable", []string{"--socket", filepath.Join(t.TempDir(), "nope.sock"), "status"}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(cliBin, tc.args...)
			err := cmd.Run()
			if got := exitCode(err); got != tc.want {
				t.Fatalf("exit = %d, want %d (err=%v)", got, tc.want, err)
			}
		})
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func hasErrors(issues []config.Issue) bool {
	for _, i := range issues {
		if i.Severity == config.SevError {
			return true
		}
	}
	return false
}
