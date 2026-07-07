package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/store"
)

// newMutableServer builds a server with a live Apply Protocol over the fake
// provider, so mutation endpoints (profile save, snapshot restore) run the
// real path: validate → snapshot → WAL → apply.
func newMutableServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	prov := fake.New()
	svc := core.New(prov, st, "test")
	proto := safety.NewProtocol(prov, st, safety.RealClock{},
		func() safety.Prober { return safety.NewFakeProber() }, "fake", nil)
	srv := NewServer(svc, st, proto, uint32(0), "test", nil)
	// httptest speaks TCP, so no UDS peer creds exist — inject root creds the
	// way the UDS listener would (requireWrite is what's under test elsewhere).
	h := srv.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), peerKey{}, peerInfo{uid: 0})
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
	t.Cleanup(ts.Close)
	return ts, st
}

func saveProfileVia(t *testing.T, ts *httptest.Server, p domain.Profile) ConfigResp {
	t.Helper()
	b, _ := json.Marshal(p)
	resp, err := http.Post(ts.URL+"/profiles?yes=1", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out ConfigResp
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("profile save status %d: %+v", resp.StatusCode, out)
	}
	return out
}

// A snapshot taken before a change must restore the profile set exactly —
// removing profiles created after it — and reconcile routes back.
func TestSnapshotRestoreBringsBackTheOldPolicy(t *testing.T) {
	ts, st := newMutableServer(t)

	// 1. Apply profile A (bypass 198.51.100.0/24). This snapshots the EMPTY
	//    pre-state, then installs A's route.
	saveProfileVia(t, ts, domain.Profile{
		ID: "p-a", Name: "alpha", Enabled: true, Mode: domain.ModeExclude,
		Gateway: "auto", Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "198.51.100.0/24"}},
	})

	// 2. Apply profile B too — snapshots the state WITH only A present.
	saveProfileVia(t, ts, domain.Profile{
		ID: "p-b", Name: "beta", Enabled: true, Mode: domain.ModeExclude,
		Gateway: "auto", Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "203.0.113.0/24"}},
	})

	snaps, err := st.ListSnapshots()
	if err != nil || len(snaps) < 2 {
		t.Fatalf("want ≥2 snapshots, got %d (err %v)", len(snaps), err)
	}
	// Newest first: snaps[0] captured {A}, snaps[1] captured {} — restore snaps[0].
	target := snaps[0]
	if len(target.Profiles) != 1 || target.Profiles[0].ID != "p-a" {
		t.Fatalf("newest snapshot should have captured only profile A: %+v", target.Profiles)
	}

	resp, err := http.Post(ts.URL+"/snapshots/"+target.ID+"/restore?yes=1", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out ConfigResp
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("restore status %d: %+v", resp.StatusCode, out)
	}
	if out.ApplyError != "" {
		t.Fatalf("unexpected apply error: %s", out.ApplyError)
	}

	profs, _ := st.ListProfiles()
	if len(profs) != 1 || profs[0].ID != "p-a" {
		t.Fatalf("restore should leave exactly profile A, got %+v", profs)
	}
}

func TestSnapshotRestoreRefusesLegacySnapshots(t *testing.T) {
	ts, st := newMutableServer(t)
	// A snapshot without profile capture (as written by older versions).
	if err := st.SaveSnapshot(domain.Snapshot{ID: "snap-legacy", CreatedAt: time.Now(), Reason: "pre-apply"}); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(ts.URL+"/snapshots/snap-legacy/restore", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("legacy snapshot restore should 400, got %d", resp.StatusCode)
	}
}

func TestSnapshotListMarksRestorable(t *testing.T) {
	ts, st := newMutableServer(t)
	_ = st.SaveSnapshot(domain.Snapshot{ID: "snap-old", CreatedAt: time.Now().Add(-time.Hour), Reason: "pre-apply"})
	_ = st.SaveSnapshot(domain.Snapshot{
		ID: "snap-new", CreatedAt: time.Now(), Reason: "pre-apply",
		Profiles: []domain.Profile{{ID: "x", Name: "x"}},
	})
	resp, err := http.Get(ts.URL + "/snapshots")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Snapshots []domain.Snapshot `json:"snapshots"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	got := map[string]bool{}
	for _, s := range body.Snapshots {
		got[s.ID] = s.Restorable
		if len(s.Profiles) != 0 || len(s.RoutesV4) != 0 {
			t.Fatalf("list view must strip payloads: %+v", s)
		}
	}
	if !got["snap-new"] || got["snap-old"] {
		t.Fatalf("restorable flags wrong: %+v", got)
	}
}

func TestPruneSnapshotsKeepsNewest(t *testing.T) {
	_, st := newMutableServer(t)
	for i := 0; i < 5; i++ {
		_ = st.SaveSnapshot(domain.Snapshot{
			ID:        string(rune('a'+i)) + "-snap",
			CreatedAt: time.Unix(int64(1000+i), 0),
			Reason:    "pre-apply",
		})
	}
	if err := st.PruneSnapshots(2); err != nil {
		t.Fatal(err)
	}
	snaps, _ := st.ListSnapshots()
	if len(snaps) != 2 {
		t.Fatalf("want 2 kept, got %d", len(snaps))
	}
	if snaps[0].ID != "e-snap" || snaps[1].ID != "d-snap" {
		t.Fatalf("kept the wrong snapshots: %+v", []string{snaps[0].ID, snaps[1].ID})
	}
}
