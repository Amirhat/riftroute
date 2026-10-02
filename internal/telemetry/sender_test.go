package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

type fakeDaemon struct {
	mu     sync.Mutex
	level  domain.TelemetryLevel
	state  State
	audit  []domain.AuditEvent
	now    time.Time
	status int
	got    [][]byte
}

func (f *fakeDaemon) env(t *testing.T, dir string) Env {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.got = append(f.got, b)
		w.WriteHeader(f.status)
	}))
	t.Cleanup(srv.Close)
	return Env{
		URL: srv.URL, HTTP: srv.Client(), Counters: OpenCounters(dir, true),
		Level:     func() domain.TelemetryLevel { f.mu.Lock(); defer f.mu.Unlock(); return f.level },
		LoadState: func() (State, error) { f.mu.Lock(); defer f.mu.Unlock(); return f.state, nil },
		SaveState: func(s State) error { f.mu.Lock(); defer f.mu.Unlock(); f.state = s; return nil },
		Gather: func(_ context.Context, _ domain.TelemetryLevel, after int64) (Inputs, int64, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			in := Inputs{App: App{Version: "0.7.0", Channel: "stable", OS: "darwin", OSMajor: 15, Arch: "arm64"}}
			last := after
			for _, ev := range f.audit {
				if ev.ID > after {
					in.Audit = append(in.Audit, ev)
					last = max(last, ev.ID)
				}
			}
			return in, last, nil
		},
		LatestAudit: func() int64 {
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.audit) == 0 {
				return 0
			}
			return f.audit[len(f.audit)-1].ID
		},
		Now: func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now },
	}
}

func (f *fakeDaemon) at(t time.Time) { f.mu.Lock(); f.now = t; f.mu.Unlock() }
func (f *fakeDaemon) sent() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.got...)
}

func applied(id int64) domain.AuditEvent {
	return domain.AuditEvent{ID: id, Actor: domain.ActorUI, Action: "apply", Result: "applied", Timing: &domain.ApplyTiming{TotalMS: 100}}
}

// Nothing goes before the user is told; then one report a day, carrying
// what was counted and the changes since the last one — exactly what the
// preview showed; a failed send keeps everything for the next day.
func TestSenderLifecycle(t *testing.T) {
	ctx := t.Context()
	start := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	f := &fakeDaemon{level: domain.TelemetryFull, now: start, status: http.StatusNoContent,
		audit: []domain.AuditEvent{applied(1), applied(2)}} // from before telemetry: never counted
	env := f.env(t, t.TempDir())
	s := NewSender(env)
	env.Counters.Inc(KeyStarts)

	s.step(ctx)
	st := f.state
	if st.FirstStart != start || st.AuditAfter != 2 || !st.NextAt.After(start.Add(16*time.Hour)) || !st.NextAt.Before(start.Add(40*time.Hour)) {
		t.Fatalf("first state %+v", st)
	}
	f.at(st.NextAt)
	s.step(ctx)
	if len(f.sent()) != 0 {
		t.Fatal("sent before the user was told")
	}
	if !s.NoticeDue() {
		t.Fatal("notice not due")
	}
	if err := s.MarkNoticeSeen(); err != nil || s.NoticeDue() {
		t.Fatal("notice not recorded")
	}

	f.audit = append(f.audit, applied(3), domain.AuditEvent{ID: 4, Action: "rollback", Result: "rolled_back", Codes: []string{"watchdog"}})
	env.Counters.Inc(TunnelKey("ikev2", TunnelConnected))
	f.at(f.state.NextAt)
	p, err := s.Preview(ctx)
	if err != nil || p.Next == nil || p.Waiting != "" || !p.NoticeSeen {
		t.Fatalf("preview %+v %v", p, err)
	}
	want, _ := json.Marshal(p.Next)
	s.step(ctx)
	got := f.sent()
	if len(got) != 1 || string(got[0]) != string(want) {
		t.Fatalf("sent\n%s\npreview showed\n%s", got, want)
	}
	r, err := Decode(got[0])
	if err != nil {
		t.Fatal(err)
	}
	if r.Applies.Applied != 1 || r.Applies.RolledBack["watchdog"] != 1 || r.Daemon.Starts != 1 || r.Tunnels["ikev2"].Connected != 1 {
		t.Fatalf("report %+v", r)
	}
	if c := env.Counters.Snapshot(); len(c) != 0 {
		t.Fatalf("counters kept after the report carried them: %v", c)
	}
	if f.state.AuditAfter != 4 || f.state.LastReport == nil || f.state.LastSent.IsZero() {
		t.Fatalf("state after send %+v", f.state)
	}

	// Not due again until the next slot.
	s.step(ctx)
	if len(f.sent()) != 1 {
		t.Fatal("sent twice in a day")
	}

	// A failed send keeps it all.
	f.status = http.StatusInternalServerError
	env.Counters.Inc(KeyStarts)
	f.at(f.state.NextAt)
	s.step(ctx)
	if len(f.sent()) != 2 || env.Counters.Snapshot()[KeyStarts] != 1 || f.state.AuditAfter != 4 {
		t.Fatalf("after a failed send: %d sent, %v, %+v", len(f.sent()), env.Counters.Snapshot(), f.state)
	}

	// The install id lasts 30 days.
	id := f.state.LastReport.Install
	f.status = http.StatusNoContent
	f.at(f.state.NextAt)
	s.step(ctx)
	if r, _ := Decode(f.sent()[2]); r.Install != id {
		t.Fatal("install id changed within 30 days")
	}
	f.at(f.state.InstallAt.Add(30*24*time.Hour + time.Minute))
	f.state.NextAt = f.now
	s.step(ctx)
	if r, _ := Decode(f.sent()[3]); r.Install == id {
		t.Fatal("install id not renewed after 30 days")
	}
}

// Off: no request, nothing counted, and on again it counts from then.
func TestSenderOff(t *testing.T) {
	ctx := t.Context()
	f := &fakeDaemon{level: domain.TelemetryOff, now: time.Now(), status: http.StatusNoContent, audit: []domain.AuditEvent{applied(1)}}
	env := f.env(t, t.TempDir())
	s := NewSender(env)
	env.Counters.Inc(KeyStarts)
	s.step(ctx)
	if c := env.Counters.Snapshot(); len(c) != 0 {
		t.Fatalf("counted while off: %v", c)
	}
	env.Counters.Inc(KeyStarts)
	f.audit = append(f.audit, applied(2))
	f.state.NextAt, f.state.NoticeSeen = f.now, f.now
	s.step(ctx)
	if len(f.sent()) != 0 || len(env.Counters.Snapshot()) != 0 || f.state.AuditAfter != 2 {
		t.Fatalf("off: %d sent, %v, %+v", len(f.sent()), env.Counters.Snapshot(), f.state)
	}
	if p, _ := s.Preview(ctx); p.Next != nil || s.NoticeDue() {
		t.Fatalf("off preview %+v", p)
	}
	f.level = domain.TelemetryBasic
	s.step(ctx)
	env.Counters.Inc(KeyStarts)
	p, err := s.Preview(ctx)
	if err != nil || p.Next == nil || p.Next.Usage != nil || p.Next.Daemon.Starts != 1 {
		t.Fatalf("basic preview %+v %v", p, err)
	}
	if strings.Contains(string(mustJSON(p.Next)), "applies") {
		t.Fatal("basic report has applies")
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestNextSlotIsTomorrow(t *testing.T) {
	now := time.Date(2026, 10, 2, 23, 59, 0, 0, time.UTC)
	for range 50 {
		n := nextSlot(now)
		if n.Before(time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)) || !n.Before(time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)) {
			t.Fatalf("slot %v", n)
		}
	}
}
