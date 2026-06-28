package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/store"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := core.New(fake.New(), st, "test")
	srv := NewServer(svc, st, 0, "test", nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestHealthz(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Fatalf("unexpected body %v", body)
	}
}

func TestStateEndpoint(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var st domain.State
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.Health.Provider != "fake" {
		t.Errorf("provider = %q", st.Health.Provider)
	}
	if !st.VPN.Active {
		t.Error("fake scenario should report VPN active")
	}
	// default v4 route should be owned by the VPN and flagged ViaVPN.
	var sawV4Default bool
	for _, d := range st.Defaults {
		if d.Family == domain.FamilyV4 {
			sawV4Default = true
			if !d.Present || !d.ViaVPN || d.Owner != domain.OwnerVPN {
				t.Errorf("v4 default unexpected: %+v", d)
			}
		}
	}
	if !sawV4Default {
		t.Error("missing v4 default route in state")
	}
}

func TestRoutesEndpointFilter(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/routes?family=v4&owner=vpn")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Routes []domain.Route `json:"routes"`
		Count  int            `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Count == 0 {
		t.Fatal("expected some vpn-owned routes")
	}
	for _, r := range body.Routes {
		if r.Owner != domain.OwnerVPN || r.Family != domain.FamilyV4 {
			t.Errorf("filter leak: %+v", r)
		}
	}
}

func TestExplainEndpoint(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Post(ts.URL+"/route/explain", "application/json", strings.NewReader(`{"target":"8.8.8.8"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var ex domain.RouteExplain
	if err := json.NewDecoder(resp.Body).Decode(&ex); err != nil {
		t.Fatal(err)
	}
	if !ex.Kernel.ViaVPN || ex.Kernel.MatchedCIDR != "0.0.0.0/0" {
		t.Fatalf("8.8.8.8 should resolve via VPN default: %+v", ex.Kernel)
	}
}
