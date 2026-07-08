package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

func postRouteOp(t *testing.T, ts *httptest.Server, req routeOpReq) (*http.Response, ConfigResp) {
	t.Helper()
	b, _ := json.Marshal(req)
	resp, err := http.Post(ts.URL+"/routes/ops?yes=1", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	var out ConfigResp
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func routesOf(t *testing.T, ts *httptest.Server) map[string]domain.Route {
	t.Helper()
	resp, err := http.Get(ts.URL + "/routes?family=v4")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Routes []domain.Route `json:"routes"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	m := map[string]domain.Route{}
	for _, r := range body.Routes {
		m[r.DstCIDR] = r
	}
	return m
}

// Deleting an external (system) route goes through the plan-level protocol
// and actually removes it — the user's headline "manage routes added outside
// the app" capability.
func TestRouteOpDeletesExternalRoute(t *testing.T) {
	ts, _ := newMutableServer(t)
	before := routesOf(t, ts)
	target, ok := before["192.168.1.0/24"]
	if !ok {
		t.Fatalf("fake scenario should list 192.168.1.0/24: %+v", before)
	}
	resp, out := postRouteOp(t, ts, routeOpReq{Action: "delete", Route: target})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %+v", resp.StatusCode, out)
	}
	if out.Result == nil || out.Result.Status == domain.TxFailed {
		t.Fatalf("route-op failed: %+v", out)
	}
	if _, still := routesOf(t, ts)["192.168.1.0/24"]; still {
		t.Fatal("route still present after delete")
	}
}

// Editing a route swaps it atomically (delete + add in one guarded tx).
func TestRouteOpReplacesExternalRoute(t *testing.T) {
	ts, _ := newMutableServer(t)
	target := routesOf(t, ts)["192.168.1.0/24"]
	updated := target
	updated.Gateway = "192.168.1.254"
	resp, out := postRouteOp(t, ts, routeOpReq{Action: "replace", Route: target, NewRoute: &updated})
	if resp.StatusCode != http.StatusOK || out.Result == nil || out.Result.Status == domain.TxFailed {
		t.Fatalf("replace failed: status %d %+v", resp.StatusCode, out)
	}
	after := routesOf(t, ts)
	got, ok := after["192.168.1.0/24"]
	if !ok || got.Gateway != "192.168.1.254" {
		t.Fatalf("edited route not in table: %+v", got)
	}
	if got.Owner == domain.OwnerRiftRoute {
		t.Fatalf("edited external route must NOT become riftroute-managed: %+v", got)
	}
}

// The one hard guardrail: removing a main-table default without a replacement
// is refused (an edit that re-adds one is fine).
func TestRouteOpRefusesRemovingDefaultRoute(t *testing.T) {
	ts, _ := newMutableServer(t)
	def := routesOf(t, ts)["0.0.0.0/0"]
	_, out := postRouteOp(t, ts, routeOpReq{Action: "delete", Route: def})
	if len(out.Result.Violations) == 0 || out.Result.Violations[0].Rule != "keep-default-route" {
		t.Fatalf("expected keep-default-route violation, got %+v", out.Result)
	}
	if _, still := routesOf(t, ts)["0.0.0.0/0"]; !still {
		t.Fatal("default route was removed despite the guardrail")
	}

	// Editing the default (delete+add) passes the guardrail.
	updated := def
	updated.Gateway = "10.8.0.99"
	resp, out2 := postRouteOp(t, ts, routeOpReq{Action: "replace", Route: def, NewRoute: &updated})
	if resp.StatusCode != http.StatusOK || out2.Result == nil || len(out2.Result.Violations) > 0 {
		t.Fatalf("default-route edit should be allowed: %+v", out2)
	}
}

// A non-canonical /0 (host bits set) must NOT slip past the default-route
// guardrail: the kernel masks it to the real default, so the guard must too.
func TestRouteOpRefusesNonCanonicalDefault(t *testing.T) {
	ts, _ := newMutableServer(t)
	sneaky := domain.Route{DstCIDR: "128.0.0.0/0", Iface: "en0", Family: domain.FamilyV4}
	_, out := postRouteOp(t, ts, routeOpReq{Action: "delete", Route: sneaky})
	if out.Result == nil || len(out.Result.Violations) == 0 || out.Result.Violations[0].Rule != "keep-default-route" {
		t.Fatalf("non-canonical default delete must be refused, got %+v", out.Result)
	}
	if _, still := routesOf(t, ts)["0.0.0.0/0"]; !still {
		t.Fatal("default route removed via a non-canonical /0")
	}
}

// Managed routes are refused — they belong to profiles.
func TestRouteOpRefusesManagedRoutes(t *testing.T) {
	ts, _ := newMutableServer(t)
	saveProfileVia(t, ts, domain.Profile{
		ID: "p-x", Name: "xray", Enabled: true, Mode: domain.ModeExclude,
		Gateway: "auto", Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "198.51.100.0/24"}},
	})
	managed, ok := routesOf(t, ts)["198.51.100.0/24"]
	if !ok {
		t.Fatal("managed route not installed")
	}
	resp, _ := postRouteOp(t, ts, routeOpReq{Action: "delete", Route: managed})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("managed route delete should 409, got %d", resp.StatusCode)
	}

	// The destination-based guard must hold even when the caller perturbs the
	// gateway/iface (so a full-tuple check would have missed it).
	perturbed := managed
	perturbed.Gateway = "9.9.9.9"
	perturbed.Iface = "en0"
	perturbed.Owner = ""
	resp, _ = postRouteOp(t, ts, routeOpReq{Action: "delete", Route: perturbed})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("managed dest with perturbed next-hop should still 409, got %d", resp.StatusCode)
	}
}
