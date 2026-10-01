package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/core"
	"github.com/Amirhat/riftroute/internal/dns"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/progress"
	"github.com/Amirhat/riftroute/internal/provider/fake"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/store"
)

// progressServer is a mutable server whose domain lookups answer from a
// fake resolver; it returns the protocol so a test can hold the apply lock.
func progressServer(t *testing.T) (*httptest.Server, *store.Store, *safety.Protocol) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	prov := fake.New()
	svc := core.New(prov, st, "test")
	res := dns.NewFakeResolver()
	res.Set("a.example", "203.0.113.10")
	res.Set("b.example", "203.0.113.11")
	svc.SetResolver(dns.NewCache(res, time.Minute))
	proto := safety.NewProtocol(prov, st, safety.RealClock{},
		func() safety.Prober { return safety.NewFakeProber() }, "fake", nil)
	srv := NewServer(svc, st, proto, uint32(0), "test", nil)
	h := srv.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), peerKey{}, peerInfo{uid: 0})))
	}))
	t.Cleanup(ts.Close)
	return ts, st, proto
}

// watchProgress collects the apply_progress events on the stream.
func watchProgress(t *testing.T, ts *httptest.Server) func() []domain.ApplyProgress {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []domain.ApplyProgress
	ready := make(chan struct{})
	go func() {
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		once := sync.Once{}
		for sc.Scan() {
			line, ok := strings.CutPrefix(sc.Text(), "data: ")
			if !ok {
				continue
			}
			once.Do(func() { close(ready) }) // the hello: subscribed
			var ev domain.Event
			if json.Unmarshal([]byte(line), &ev) != nil || ev.Type != domain.EventApplyProgress {
				continue
			}
			var p domain.ApplyProgress
			if json.Unmarshal(ev.Data, &p) == nil {
				mu.Lock()
				got = append(got, p)
				mu.Unlock()
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("no event stream")
	}
	return func() []domain.ApplyProgress {
		mu.Lock()
		defer mu.Unlock()
		return append([]domain.ApplyProgress(nil), got...)
	}
}

func applyTagged(t *testing.T, ts *httptest.Server, id string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/apply", bytes.NewReader([]byte(`{"yes":true}`)))
	if id != "" {
		req.Header.Set(progress.Header, id)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

// steps lists each step once, in the order they first came, for id.
func steps(ps []domain.ApplyProgress, id string) []domain.ApplyStep {
	var out []domain.ApplyStep
	for _, p := range ps {
		if p.ID == id && (len(out) == 0 || out[len(out)-1] != p.Step) {
			out = append(out, p.Step)
		}
	}
	return out
}

// A change the app tagged reports its steps on the event stream as it goes:
// looking up the profiles' domains (counted), checking, changing routes
// (counted, to the last one). An untagged change reports nothing.
func TestApplyReportsItsSteps(t *testing.T) {
	ts, st, _ := progressServer(t)
	if err := st.UpsertProfile(domain.Profile{ID: "p1", Name: "p1", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleDomain, Value: "a.example"}, {Type: domain.RuleDomain, Value: "b.example"}, {Type: domain.RuleCIDR, Value: "198.51.100.0/24"}}}); err != nil {
		t.Fatal(err)
	}
	got := watchProgress(t, ts)
	applyTagged(t, ts, "")
	applyTagged(t, ts, "ui-1")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ps := got(); len(ps) > 0 && ps[len(ps)-1].Step == domain.StepChecking {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	ps := got()
	for _, p := range ps {
		if p.ID != "ui-1" {
			t.Fatalf("an untagged change reported: %+v", p)
		}
	}
	// The first apply made the routes; the tagged one finds nothing to change.
	if s := steps(ps, "ui-1"); len(s) != 2 || s[0] != domain.StepResolving || s[1] != domain.StepChecking {
		t.Fatalf("steps = %v (%+v)", s, ps)
	}
	if first := ps[0]; first.Total != 2 {
		t.Errorf("resolving counted %d names, want 2", first.Total)
	}

	// Now a change with routes to make: counted to the last one.
	if err := st.UpsertProfile(domain.Profile{ID: "p2", Name: "p2", Enabled: true, Mode: domain.ModeExclude, Gateway: "auto",
		Rules: []domain.Rule{{Type: domain.RuleCIDR, Value: "192.0.2.0/25"}, {Type: domain.RuleCIDR, Value: "192.0.2.128/26"}}}); err != nil {
		t.Fatal(err)
	}
	applyTagged(t, ts, "ui-2")
	var last domain.ApplyProgress
	for time.Now().Before(deadline) {
		for _, p := range got() {
			if p.ID == "ui-2" {
				last = p
			}
		}
		if last.Step == domain.StepApplying && last.Done == last.Total {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if last.Step != domain.StepApplying || last.Total != 2 || last.Done != 2 {
		t.Fatalf("the last step = %+v", last)
	}
}

// A change that has to wait for another says so first.
func TestApplyReportsWaitingBehindAnotherChange(t *testing.T) {
	ts, _, proto := progressServer(t)
	got := watchProgress(t, ts)
	release, ok, why := proto.TryQuiesce(0)
	if !ok {
		t.Fatal(why)
	}
	done := make(chan struct{})
	go func() { applyTagged(t, ts, "ui-w"); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(got()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if ps := got(); len(ps) == 0 || ps[0] != (domain.ApplyProgress{ID: "ui-w", Step: domain.StepWaiting}) {
		t.Fatalf("progress = %+v", ps)
	}
	release()
	<-done
	if s := steps(got(), "ui-w"); len(s) < 2 || s[1] != domain.StepChecking {
		t.Errorf("after the wait: %v", s)
	}
}
