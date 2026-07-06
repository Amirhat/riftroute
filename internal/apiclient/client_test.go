package apiclient

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/api"
	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/store"
)

// serveTest spins up the real API server over a real UDS and returns a client
// pointed at it. Exercises the full transport, including peer-cred (same user).
func serveTest(t *testing.T) (*Client, *api.Server, *store.Store) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "rr.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	prov := fake.New()
	svc := core.New(prov, st, "test")
	proto := safety.NewProtocol(prov, st, safety.RealClock{}, nil, "fake", nil)
	srv := api.NewServer(svc, st, proto, uint32(os.Getuid()), "test", nil)
	srv.SetAutoApplyControl(svc.SetAutoApply) // mirrors the daemon wiring

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		_ = st.Close()
	})
	return New(sock), srv, st
}

func TestClientReadRoundTrip(t *testing.T) {
	c, _, _ := serveTest(t)
	ctx := context.Background()

	ver, err := c.Ping(ctx)
	if err != nil || ver != "test" {
		t.Fatalf("ping: ver=%q err=%v", ver, err)
	}
	st, err := c.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Health.Provider != "fake" || !st.VPN.Active {
		t.Fatalf("unexpected state: %+v", st.Health)
	}
	routes, err := c.Routes(ctx, domain.FamilyV4, domain.OwnerVPN)
	if err != nil || len(routes) == 0 {
		t.Fatalf("routes: %v len=%d", err, len(routes))
	}
	ex, err := c.Explain(ctx, "192.168.1.10")
	if err != nil {
		t.Fatal(err)
	}
	if ex.Kernel.Iface != "en0" || ex.Kernel.ViaVPN {
		t.Fatalf("explain LAN should be direct via en0: %+v", ex.Kernel)
	}
}

func TestClientApplyConfirmPanic(t *testing.T) {
	c, _, st := serveTest(t)
	ctx := context.Background()

	// Seed an enabled exclude profile so apply has something to install.
	if err := st.UpsertProfile(domain.Profile{
		ID: "p1", Name: "direct", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "9.9.9.0/24"}},
	}); err != nil {
		t.Fatal(err)
	}

	// dry-run first: plan should show one add, nothing installed.
	plan, diff, err := c.Plan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Ops) != 1 || diff.Adds != 1 {
		t.Fatalf("plan should add 1 route, got ops=%d adds=%d", len(plan.Ops), diff.Adds)
	}

	// apply (non-interactive), then confirm to resolve promptly.
	res, err := c.Apply(ctx, ApplyOptions{Yes: true})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Status != domain.TxPending || res.TxID == "" {
		t.Fatalf("apply result: %+v", res)
	}
	managed, _ := c.Routes(ctx, domain.FamilyV4, domain.OwnerRiftRoute)
	if len(managed) != 1 || managed[0].DstCIDR != "9.9.9.0/24" {
		t.Fatalf("expected the bypass route installed, got %+v", managed)
	}
	if result, err := c.Confirm(ctx, res.TxID); err != nil || result != domain.TxCommitted {
		t.Fatalf("confirm: result=%s err=%v", result, err)
	}

	// panic removes it.
	if err := c.Panic(ctx); err != nil {
		t.Fatal(err)
	}
	managed, _ = c.Routes(ctx, domain.FamilyV4, domain.OwnerRiftRoute)
	if len(managed) != 0 {
		t.Fatalf("panic should remove managed routes, got %+v", managed)
	}
}

// TestClientSaveDeleteProfile exercises the interactive GUI builder's backend
// path end-to-end over the real transport: dry-run preview (no persist), a real
// save (validate → persist → apply → confirm), validation + name-conflict errors,
// and delete (remove + reconcile).
func TestClientSaveDeleteProfile(t *testing.T) {
	c, _, st := serveTest(t)
	ctx := context.Background()

	valid := domain.Profile{
		Name: "builder-work", Description: "from the GUI builder", Enabled: true,
		Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{
			{Type: domain.RuleCIDR, Value: "9.9.9.0/24"},
			{Type: domain.RuleIP, Value: "1.1.1.1"},
		},
	}

	// dry-run: previews a 2-route plan and persists NOTHING.
	dr, err := c.SaveProfile(ctx, valid, true, false)
	if err != nil {
		t.Fatalf("dry-run save: %v", err)
	}
	if dr.Plan == nil || len(dr.Plan.Ops) != 2 {
		t.Fatalf("dry-run should preview 2 route adds, got %+v", dr.Plan)
	}
	if _, gerr := st.GetProfile("builder-work"); gerr == nil {
		t.Fatal("dry-run must NOT persist the profile")
	}

	// real save: persists + applies (non-interactive → pending); confirm to resolve.
	res, err := c.SaveProfile(ctx, valid, false, true)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if res.Result == nil || res.Result.TxID == "" {
		t.Fatalf("expected a pending tx, got %+v", res.Result)
	}
	if _, gerr := st.GetProfile("builder-work"); gerr != nil {
		t.Fatalf("profile should be persisted: %v", gerr)
	}
	if _, cerr := c.Confirm(ctx, res.Result.TxID); cerr != nil {
		t.Fatalf("confirm: %v", cerr)
	}
	managed, _ := c.Routes(ctx, domain.FamilyV4, domain.OwnerRiftRoute)
	if len(managed) != 2 {
		t.Fatalf("expected 2 managed routes after save, got %+v", managed)
	}

	// invalid profile (empty name + bad CIDR): 400 with issues, nothing persisted.
	bad := domain.Profile{Mode: domain.ModeExclude, Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "999.999.999"}}}
	ir, ierr := c.SaveProfile(ctx, bad, true, false)
	if ierr == nil {
		t.Fatal("invalid profile should return an error")
	}
	if len(ir.Issues) == 0 {
		t.Fatalf("invalid profile should carry issues, got %+v", ir)
	}

	// name owned by a different profile → friendly conflict issue.
	dup := valid
	dup.ID = "gui:someone-else"
	cr, cerr := c.SaveProfile(ctx, dup, true, false)
	if cerr == nil {
		t.Fatal("duplicate name should error")
	}
	sawConflict := false
	for _, is := range cr.Issues {
		if strings.Contains(is.Msg, "already uses the name") {
			sawConflict = true
		}
	}
	if !sawConflict {
		t.Fatalf("expected a name-conflict issue, got %+v", cr.Issues)
	}

	// delete: reconciles the removal; confirm; profile + routes gone.
	del, derr := c.DeleteProfile(ctx, "builder-work", true)
	if derr != nil {
		t.Fatalf("delete: %v", derr)
	}
	if del.Result != nil && del.Result.TxID != "" {
		if _, cerr := c.Confirm(ctx, del.Result.TxID); cerr != nil {
			t.Fatalf("confirm delete: %v", cerr)
		}
	}
	if _, gerr := st.GetProfile("builder-work"); gerr == nil {
		t.Fatal("profile should be deleted")
	}
	managed, _ = c.Routes(ctx, domain.FamilyV4, domain.OwnerRiftRoute)
	if len(managed) != 0 {
		t.Fatalf("delete should remove managed routes, got %+v", managed)
	}
}

// TestClientListsCRUD exercises the GUI lists manager's backend: save (validate,
// staging only), reference protection on delete, and delete.
func TestClientListsCRUD(t *testing.T) {
	c, _, st := serveTest(t)
	ctx := context.Background()

	// invalid list (no entries, bad entry) → ValidationError with issues.
	if _, err := c.SaveList(ctx, domain.List{Name: "bad", Static: []string{"999.999.999"}}); err == nil {
		t.Fatal("invalid list should be rejected")
	} else {
		var verr *ValidationError
		if !errors.As(err, &verr) || len(verr.Issues) == 0 {
			t.Fatalf("want ValidationError with issues, got %T %v", err, err)
		}
	}

	// valid static list saves and is staging-only (no kernel mutation to confirm).
	saved, err := c.SaveList(ctx, domain.List{Name: "corp", Static: []string{"10.0.0.0/8", "192.168.0.0/16"}})
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if saved.Name != "corp" || len(saved.Static) != 2 {
		t.Fatalf("saved list wrong: %+v", saved)
	}

	// a profile referencing the list blocks deletion (409 with a friendly message).
	if err := st.UpsertProfile(domain.Profile{ID: "p1", Name: "uses-corp", Lists: []string{"corp"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteList(ctx, "corp"); err == nil {
		t.Fatal("delete of a referenced list must be refused")
	} else if !strings.Contains(err.Error(), "uses-corp") {
		t.Fatalf("refusal should name the referencing profile, got: %v", err)
	}

	// removing the reference unblocks deletion.
	if err := st.DeleteProfile("uses-corp"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteList(ctx, "corp"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	ls, _ := c.Lists(ctx)
	if len(ls) != 0 {
		t.Fatalf("list should be gone, got %+v", ls)
	}
}

// TestClientSplitDNS exercises the Settings editor's backend: validate → persist
// → apply, read-back, and clear. The fake manager means no host DNS is touched.
func TestClientSplitDNS(t *testing.T) {
	c, _, st := serveTest(t)
	ctx := context.Background()

	// invalid domain/resolver → ValidationError.
	if _, err := c.SetSplitDNS(ctx, []domain.SplitDNSRoute{{Domain: "not_a_domain", Resolver: "nope"}}); err == nil {
		t.Fatal("invalid split-DNS should be rejected")
	}

	routes := []domain.SplitDNSRoute{{Domain: "corp.example.com", Resolver: "10.0.0.53"}}
	if _, err := c.SetSplitDNS(ctx, routes); err != nil {
		t.Fatalf("set: %v", err)
	}
	// persisted (survives restarts) …
	persisted, err := st.LoadSplitDNS()
	if err != nil || len(persisted) != 1 || persisted[0].Resolver != "10.0.0.53" {
		t.Fatalf("persisted wrong: %+v err=%v", persisted, err)
	}
	// … and readable over the API.
	got, err := c.SplitDNS(ctx)
	if err != nil || len(got) != 1 || got[0].Domain != "corp.example.com" {
		t.Fatalf("get: %+v err=%v", got, err)
	}

	// empty set clears.
	if _, err := c.SetSplitDNS(ctx, nil); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got, _ := c.SplitDNS(ctx); len(got) != 0 {
		t.Fatalf("expected cleared, got %+v", got)
	}
}

// TestClientAutoApplyToggle exercises the Settings switch's backend: runtime
// toggle, reflected in State, persisted for the next daemon start.
func TestClientAutoApplyToggle(t *testing.T) {
	c, _, st := serveTest(t)
	ctx := context.Background()

	on, err := c.SetAutoApply(ctx, true)
	if err != nil || !on {
		t.Fatalf("enable: on=%v err=%v", on, err)
	}
	if s, _ := c.State(ctx); !s.AutoApply {
		t.Fatal("state should report auto-apply on")
	}
	off, err := c.SetAutoApply(ctx, false)
	if err != nil || off {
		t.Fatalf("disable: on=%v err=%v", off, err)
	}
	if s, _ := c.State(ctx); s.AutoApply {
		t.Fatal("state should report auto-apply off")
	}
	// persisted: the daemon reads this at startup (wins over the flag default).
	if v, ok, _ := st.GetSetting("auto_apply"); !ok || v != "false" {
		t.Fatalf("setting not persisted: %q ok=%v", v, ok)
	}
}

func TestClientUnreachable(t *testing.T) {
	c := New(filepath.Join(t.TempDir(), "nonexistent.sock"))
	_, err := c.Ping(context.Background())
	if !errors.Is(err, ErrDaemonUnreachable) {
		t.Fatalf("expected ErrDaemonUnreachable, got %v", err)
	}
}

func TestClientEventsStream(t *testing.T) {
	c, srv, _ := serveTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	got := make(chan domain.EventType, 8)
	go func() {
		_ = c.Events(ctx, func(ev domain.Event) {
			select {
			case got <- ev.Type:
			default:
			}
		})
	}()

	// Give the stream a moment to connect, then push a state event.
	deadline := time.After(2 * time.Second)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	var sawState bool
	for !sawState {
		select {
		case <-deadline:
			t.Fatal("did not receive a state event in time")
		case <-tick.C:
			srv.BroadcastState(context.Background())
		case et := <-got:
			if et == domain.EventState {
				sawState = true
			}
		}
	}
}
