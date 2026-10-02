package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/telemetry"
)

// report is a valid full report from install n for day.
func report(n int, day, version string) telemetry.Report {
	return telemetry.Report{
		Schema: telemetry.Schema, Install: fmt.Sprintf("%032x", n), Level: "full", Day: day,
		App:     telemetry.App{Version: version, Channel: "stable", OS: "darwin", OSMajor: 15, Arch: "arm64", Service: true},
		Daemon:  telemetry.Daemon{Starts: 2},
		Updates: telemetry.Updates{Installed: 1},
		Usage: &telemetry.Usage{
			Profiles: 3, ProfilesEnabled: 2, ProfileModes: map[string]int{"exclude": 2}, Rules: map[string]int{"cidr": 4, "wildcard": 1},
			Tunnels: map[string]int{"ikev2": 1}, KillSwitch: true, AutoApply: true,
		},
		Applies: &telemetry.Applies{Applied: 10, Refused: map[string]int{"gateway-capture": 1}, RolledBack: map[string]int{}, MS: map[string]int{"lt250": 10}},
		Tunnels: map[string]telemetry.TunnelSessions{"ikev2": {Connected: 3, Failed: map[string]int{"cert": 1}}},
	}
}

func (e *testEnv) post(target, contentType, body string, header ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", target, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:50000"
	r.Header.Set("CF-Connecting-IP", e.ip)
	r.Header.Set("Content-Type", contentType)
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func (e *testEnv) send(r telemetry.Report) *httptest.ResponseRecorder {
	b, _ := json.Marshal(r)
	return e.post("/api/v1/telemetry", "application/json", string(b))
}

func TestTelemetryReportIsTakenStrictly(t *testing.T) {
	e := newEnv(t, "")
	today := e.now.UTC().Format(time.DateOnly)
	if w := e.send(report(1, today, "0.7.0")); w.Code != http.StatusNoContent {
		t.Fatalf("valid report: %d %s", w.Code, w.Body)
	}
	good, _ := json.Marshal(report(2, today, "0.7.0"))
	for name, c := range map[string]struct {
		ct, body string
		want     int
	}{
		"not JSON":      {"text/plain", string(good), http.StatusUnsupportedMediaType},
		"unknown field": {"application/json", strings.Replace(string(good), `"schema":1`, `"schema":1,"hostname":"laptop"`, 1), 400},
		"unknown key":   {"application/json", strings.Replace(string(good), `"cidr":4`, `"10.0.0.0/8":4`, 1), 400},
		"a name":        {"application/json", strings.Replace(string(good), `"channel":"stable"`, `"channel":"office"`, 1), 400},
		"two objects":   {"application/json", string(good) + string(good), 400},
		"too large":     {"application/json", string(good[:len(good)-1]) + `,"x":"` + strings.Repeat("a", telemetry.MaxReportBytes) + `"}`, http.StatusRequestEntityTooLarge},
		"old day":       {"application/json", strings.Replace(string(good), today, "2026-09-01", 1), 400},
		"future day":    {"application/json", strings.Replace(string(good), today, "2026-09-25", 1), 400},
	} {
		if w := e.post("/api/v1/telemetry", c.ct, c.body); w.Code != c.want {
			t.Errorf("%s: %d, want %d (%s)", name, w.Code, c.want, w.Body)
		}
	}
	reps, _ := e.srv.st.reports("2026-01-01", "2026-12-31")
	if len(reps) != 1 {
		t.Fatalf("%d reports stored, want only the valid one", len(reps))
	}
	// A repeat the same day replaces it.
	r := report(1, today, "0.7.1")
	if w := e.send(r); w.Code != http.StatusNoContent {
		t.Fatal(w.Code)
	}
	reps, _ = e.srv.st.reports(today, today)
	if len(reps) != 1 || reps[0].App.Version != "0.7.1" {
		t.Fatalf("repeat: %+v", reps)
	}
	if strings.Contains(e.logs.String(), e.ip) {
		t.Fatalf("the sender's address reached the log: %s", e.logs)
	}
}

func TestTelemetryIsThrottledPerClient(t *testing.T) {
	e := newEnv(t, "")
	today := e.now.UTC().Format(time.DateOnly)
	for i := range 30 {
		if w := e.send(report(i+1, today, "0.7.0")); w.Code != http.StatusNoContent {
			t.Fatalf("report %d: %d", i, w.Code)
		}
	}
	if w := e.send(report(99, today, "0.7.0")); w.Code != http.StatusTooManyRequests {
		t.Fatalf("31st in the hour: %d", w.Code)
	}
	e.ip = "198.51.100.9"
	if w := e.send(report(100, today, "0.7.0")); w.Code != http.StatusNoContent {
		t.Fatalf("another client: %d", w.Code)
	}
}

func TestTelemetryIsKept180Days(t *testing.T) {
	e := newEnv(t, "")
	if err := e.srv.st.putReport(ptr(report(1, "2026-03-01", "0.5.0")), e.now); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.st.putReport(ptr(report(2, "2026-09-01", "0.6.0")), e.now); err != nil {
		t.Fatal(err)
	}
	e.srv.maintain()
	reps, _ := e.srv.st.reports("2026-01-01", "2026-12-31")
	if len(reps) != 1 || reps[0].Day != "2026-09-01" {
		t.Fatalf("after the sweep: %+v", reps)
	}
}

func ptr[T any](v T) *T { return &v }

func TestTelemetrySummaryNeedsTheToken(t *testing.T) {
	e := newEnv(t, "")
	get := func(auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api/v1/telemetry/summary?days=7", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		return w
	}
	if w := get("Bearer anything"); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token set up: %d", w.Code)
	}
	token, err := NewTelemetryToken(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, auth := range []string{"", "Bearer ", "Bearer wrong", token, "Basic " + token} {
		if w := get(auth); w.Code != http.StatusUnauthorized {
			t.Errorf("%q: %d", auth, w.Code)
		}
	}
	e.send(report(1, e.now.UTC().Format(time.DateOnly), "0.7.0"))
	w := get("Bearer " + token)
	var sum Summary
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &sum) != nil || sum.Installs != 1 || sum.Days != 7 {
		t.Fatalf("summary: %d %s", w.Code, w.Body)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("the summary may be cached")
	}
	// A new token replaces the old one.
	if _, err := NewTelemetryToken(e.dir); err != nil {
		t.Fatal(err)
	}
	if w := get("Bearer " + token); w.Code != http.StatusUnauthorized {
		t.Fatalf("old token still works: %d", w.Code)
	}
}

func TestTelemetryDashboard(t *testing.T) {
	e := newEnv(t, "correct horse battery")
	if w := e.do("GET", "/admin/telemetry", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("anonymous dashboard: %d", w.Code)
	}
	today := e.now.UTC().Format(time.DateOnly)
	e.send(report(1, today, "0.7.0"))
	r := report(2, today, "0.6.1")
	r.Level, r.Usage, r.Applies, r.Tunnels = "basic", nil, nil, nil
	e.send(r)
	sess := cookie(e.login("correct horse battery"), sessionCookie)
	w := e.do("GET", "/admin/telemetry?days=30", nil, sess)
	body := w.Body.String()
	for _, want := range []string{"0.7.0", "0.6.1", "ikev2", "gateway-capture", "darwin 15", "kill switch", `aria-current="page">30 days`} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard lacks %q", want)
		}
	}
	if w.Code != 200 || strings.Contains(body, "<script") {
		t.Fatalf("dashboard: %d", w.Code)
	}
	if a := e.do("GET", "/admin", nil, sess).Body.String(); !strings.Contains(a, "Open the telemetry dashboard") {
		t.Fatal("the overview doesn't link the dashboard")
	}
}

func TestSummaryFlagsAWorseVersion(t *testing.T) {
	day := "2026-09-23"
	var reps []telemetry.Report
	for i := range 10 {
		old := report(i+1, day, "0.6.1")
		old.Daemon = telemetry.Daemon{Starts: 3}
		reps = append(reps, old)
		bad := report(i+100, day, "0.7.0")
		bad.Daemon = telemetry.Daemon{Starts: 3, Unclean: 1}
		bad.Updates.RolledBackHealth = 0
		reps = append(reps, bad)
	}
	reps[0].Updates.RolledBackHealth = 1 // an install went back to 0.6.1
	d, _ := time.Parse(time.DateOnly, day)
	s, err := summarize(newestFirst(reps), d.AddDate(0, 0, -6), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Versions) != 2 || s.Versions[0].Version != "0.7.0" || s.Versions[0].Installs != 10 {
		t.Fatalf("versions %+v", s.Versions)
	}
	var unclean, rollback bool
	for _, f := range s.Flags {
		unclean = unclean || f.Version == "0.7.0" && strings.Contains(f.What, "unclean")
		rollback = rollback || strings.Contains(f.What, "rolled back")
	}
	if !unclean || !rollback {
		t.Fatalf("flags %+v", s.Flags)
	}
	if s.Usage.Installs != 20 || s.Usage.KillSwitch != 20 || s.Usage.RuleKinds["wildcard"] != 20 || s.Daily[6].Installs != 20 {
		t.Fatalf("usage %+v daily %+v", s.Usage, s.Daily)
	}
	if r := s.Tunnels["ikev2"]; r.Connected != 60 || r.Failed != 20 || r.ConnectRate == nil || pct(r.ConnectRate) != "75%" {
		t.Fatalf("tunnels %+v", r)
	}
}

func TestVersionsSortNewestFirst(t *testing.T) {
	vs := []VersionSummary{{Version: "0.6.1"}, {Version: "dev"}, {Version: "0.10.0"}, {Version: "0.7.0"}}
	sortVersions(vs)
	var got []string
	for _, v := range vs {
		got = append(got, v.Version)
	}
	if strings.Join(got, " ") != "0.10.0 0.7.0 0.6.1 dev" {
		t.Fatal(got)
	}
}

// newestFirst yields reps (oldest first) as the store does for a summary.
func newestFirst(reps []telemetry.Report) func(func(telemetry.Report)) error {
	return func(fn func(telemetry.Report)) error {
		for i := len(reps) - 1; i >= 0; i-- {
			fn(reps[i])
		}
		return nil
	}
}

// Reports can't take the shared host's disk, however many are sent: at
// most the daily cap is kept (a repeat replaces its own and doesn't count),
// and none past the database's size cap or below the disk's free floor. A
// refusal is a 503 (the client sends it again later), logged at most hourly
// and without the sender.
func TestTelemetryCantFillTheDisk(t *testing.T) {
	cap, maxDB, minFree := telemetryDailyCap, telemetryMaxDB, telemetryMinFree
	t.Cleanup(func() { telemetryDailyCap, telemetryMaxDB, telemetryMinFree = cap, maxDB, minFree })
	e := newEnv(t, "")
	today := e.now.UTC().Format(time.DateOnly)
	telemetryDailyCap = 2
	for i, want := range []int{204, 204, 503} {
		e.ip = fmt.Sprintf("198.51.100.%d", i+1)
		if w := e.send(report(i+1, today, "0.7.0")); w.Code != want {
			t.Fatalf("report %d: %d, want %d", i+1, w.Code, want)
		}
	}
	if w := e.send(report(1, today, "0.7.1")); w.Code != 204 {
		t.Fatalf("a repeat at the cap: %d", w.Code)
	}
	telemetryDailyCap = 100
	telemetryMaxDB = 1
	if w := e.send(report(9, today, "0.7.0")); w.Code != 503 {
		t.Fatalf("past the database's cap: %d", w.Code)
	}
	telemetryMaxDB = maxDB
	telemetryMinFree = 1 << 50 // more than the env's 42 GiB free
	if w := e.send(report(10, today, "0.7.0")); w.Code != 503 {
		t.Fatalf("low on disk: %d", w.Code)
	}
	telemetryMinFree = minFree
	if w := e.send(report(11, today, "0.7.0")); w.Code != 204 {
		t.Fatalf("with room again: %d", w.Code)
	}
	if n := strings.Count(e.logs.String(), "telemetry reports refused"); n != 1 {
		t.Errorf("refusals logged %d times in an hour, want once:\n%s", n, e.logs)
	}
	if strings.Contains(e.logs.String(), "198.51.100") {
		t.Error("the sender's address reached the log")
	}
	if reps, _ := e.srv.st.reports(today, today); len(reps) != 3 {
		t.Fatalf("%d reports kept, want 3", len(reps))
	}
}

// A summary is worked out at most once a minute per window.
func TestTelemetrySummaryIsCached(t *testing.T) {
	e := newEnv(t, "")
	today := e.now.UTC().Format(time.DateOnly)
	e.send(report(1, today, "0.7.0"))
	first, err := e.srv.summary(7)
	if err != nil || first.Installs != 1 {
		t.Fatalf("%+v %v", first, err)
	}
	e.send(report(2, today, "0.7.0"))
	if s, _ := e.srv.summary(7); s.Installs != 1 {
		t.Fatalf("not cached: %d", s.Installs)
	}
	e.now = e.now.Add(summaryTTL)
	if s, _ := e.srv.summary(7); s.Installs != 2 {
		t.Fatalf("stale after the TTL: %d", s.Installs)
	}
}
