package telemetry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// DefaultURL is where reports go.
const DefaultURL = "https://riftroute.tellnew.tech/api/v1/telemetry"

// Timing (vars for tests).
var (
	// tick is how often the sender looks at the level, keeps the counters
	// and sees whether a report is due.
	tick = time.Minute
	// installTTL: the install id is replaced this often.
	installTTL = 30 * 24 * time.Hour
	// noticeGrace: where nobody can be told (no app or CLI ever runs),
	// reports start this long after the first start.
	noticeGrace = 7 * 24 * time.Hour
	// sendTimeout bounds one report's request.
	sendTimeout = 30 * time.Second
	// retryMin and retryMax bound the wait before a report the server
	// didn't answer is sent again.
	retryMin, retryMax = 10 * time.Minute, 4 * time.Hour
)

// State is what the daemon keeps between reports (in its settings).
type State struct {
	Install    string    `json:"install,omitempty"`
	InstallAt  time.Time `json:"install_at,omitzero"`
	FirstStart time.Time `json:"first_start,omitzero"`
	NextAt     time.Time `json:"next_at,omitzero"`
	// AuditAfter is the last audit event a report counted.
	AuditAfter int64     `json:"audit_after"`
	LastSent   time.Time `json:"last_sent,omitzero"`
	LastReport *Report   `json:"last_report,omitempty"`
	NoticeSeen time.Time `json:"notice_seen,omitzero"`

	// Pending is a report sent without an answer. It's sent again, the
	// same (its day too), until the server takes it: the server keeps one
	// report per install and day, so a copy it already had is replaced,
	// not counted twice.
	Pending *Report `json:"pending,omitempty"`
	// PendingID names it (locally); PendingCounts are the counters it
	// carries, PendingAudit the newest audit event it counts.
	PendingID     string         `json:"pending_id,omitempty"`
	PendingCounts map[string]int `json:"pending_counts,omitempty"`
	PendingAudit  int64          `json:"pending_audit,omitempty"`
	PendingTries  int            `json:"pending_tries,omitempty"`
	// Taken is a report the server took whose counts may still be on the
	// counters: they're settled by its id (once), then it's cleared.
	Taken       string         `json:"taken,omitempty"`
	TakenCounts map[string]int `json:"taken_counts,omitempty"`
}

// Preview is what the user is shown: the exact report that would go now,
// and what went last.
type Preview struct {
	Level domain.TelemetryLevel `json:"level"`
	// Next is the report as it would be sent now (none while off).
	Next   *Report    `json:"next,omitempty"`
	NextAt *time.Time `json:"next_at,omitempty"`
	// Waiting says why nothing is sent yet, if so.
	Waiting    string     `json:"waiting,omitempty"`
	LastSent   *time.Time `json:"last_sent,omitempty"`
	Last       *Report    `json:"last,omitempty"`
	NoticeSeen bool       `json:"notice_seen"`
}

// Env is what the sender needs from the daemon.
type Env struct {
	URL      string
	HTTP     *http.Client
	Counters *Counters
	Level    func() domain.TelemetryLevel
	// LoadState and SaveState keep State (the daemon's settings).
	LoadState func() (State, error)
	SaveState func(State) error
	// Gather reads the daemon's records for a report counting audit events
	// after auditAfter; last is the newest audit id it read.
	Gather func(ctx context.Context, level domain.TelemetryLevel, auditAfter int64) (in Inputs, last int64, err error)
	// LatestAudit is the newest audit id (where counting starts).
	LatestAudit func() int64
	Now         func() time.Time
	Log         *slog.Logger
}

// Sender sends the daily report.
type Sender struct {
	env Env
	mu  sync.Mutex // one build-and-send (or state change) at a time
}

// NewSender returns a Sender.
func NewSender(env Env) *Sender {
	if env.Now == nil {
		env.Now = time.Now
	}
	if env.Log == nil {
		env.Log = slog.Default()
	}
	if env.URL == "" {
		env.URL = DefaultURL
	}
	return &Sender{env: env}
}

// Run keeps the counters in step with the level and sends a report when
// one is due, until ctx ends (then it saves the counters).
func (s *Sender) Run(ctx context.Context) {
	t := time.NewTicker(tick)
	defer t.Stop()
	defer func() { _ = s.env.Counters.Flush() }()
	for {
		s.step(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// step is one tick.
func (s *Sender) step(ctx context.Context) {
	level := s.env.Level()
	on := level != domain.TelemetryOff
	s.env.Counters.SetOn(on)
	if err := s.env.Counters.Flush(); err != nil {
		s.env.Log.Debug("telemetry counters not saved", "err", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.state()
	if err != nil {
		return
	}
	s.settle(&st)
	now := s.env.Now()
	if !on {
		// Off: nothing counted, nothing sent (not a pending report either);
		// when it's back on, it counts from then.
		if st.AuditAfter != s.env.LatestAudit() || st.Pending != nil {
			st.AuditAfter = s.env.LatestAudit()
			dropPending(&st)
			_ = s.env.SaveState(st)
		}
		return
	}
	if st.NextAt.Sub(now) > 48*time.Hour {
		// Scheduled while the clock was far ahead.
		st.NextAt = nextSlot(now)
		_ = s.env.SaveState(st)
	}
	if now.Before(st.NextAt) {
		return
	}
	if p := st.Pending; p != nil && (p.Level != string(level) || dayPast(p.Day, now)) {
		// Built at a level the user has since changed, or for a day the
		// server no longer takes: not sent again. The server may have it
		// (it didn't answer), so what it carries is taken as sent rather
		// than sent twice — a release looking a little better than it is
		// beats one looking broken.
		st.AuditAfter, st.Taken, st.TakenCounts = st.PendingAudit, st.PendingID, st.PendingCounts
		dropPending(&st)
		_ = s.env.SaveState(st)
		s.settle(&st)
	}
	if st.Pending == nil {
		if why := s.waiting(st, now); why != "" {
			st.NextAt = nextSlot(now)
			_ = s.env.SaveState(st)
			return
		}
		r, snap, last, err := s.build(ctx, &st, level, now)
		if err != nil {
			s.env.Log.Info("telemetry report not built; trying again tomorrow", "err", err)
			st.NextAt = nextSlot(now)
			_ = s.env.SaveState(st)
			return
		}
		id, err := newInstall()
		if err != nil {
			return
		}
		st.Pending, st.PendingID, st.PendingCounts, st.PendingAudit, st.PendingTries = r, id, snap, last, 0
		// Recorded before it's sent: if the daemon stops mid-send, the same
		// report goes again.
		_ = s.env.SaveState(st)
	}
	switch err := s.post(ctx, st.Pending); {
	case err == nil:
		s.env.Log.Info("telemetry report sent", "level", level, "day", st.Pending.Day)
		st.AuditAfter, st.LastSent, st.LastReport = st.PendingAudit, now, st.Pending
		st.Taken, st.TakenCounts = st.PendingID, st.PendingCounts
		dropPending(&st)
		st.NextAt = nextSlot(now)
		_ = s.env.SaveState(st) // first: a crash after it settles the counts at the next start
		s.settle(&st)
	case errors.Is(err, errRefused):
		// The server didn't take it (so it doesn't have it): its counts go
		// with the next report.
		s.env.Log.Info("telemetry report refused; its counts go with the next one", "err", err)
		dropPending(&st)
		st.NextAt = nextSlot(now)
	default:
		st.PendingTries++
		st.NextAt = now.Add(min(retryMin<<min(st.PendingTries-1, 10), retryMax))
		s.env.Log.Info("telemetry report not sent; sending it again later", "err", err, "at", st.NextAt)
	}
	_ = s.env.SaveState(st)
}

// settle takes a report the server took off the counters (once), and
// forgets it.
func (s *Sender) settle(st *State) {
	if st.Taken == "" {
		return
	}
	if err := s.env.Counters.Settle(st.Taken, st.TakenCounts); err != nil {
		return // the next tick tries again
	}
	st.Taken, st.TakenCounts = "", nil
	_ = s.env.SaveState(*st)
}

// dropPending forgets a pending report.
func dropPending(st *State) {
	st.Pending, st.PendingID, st.PendingCounts, st.PendingAudit, st.PendingTries = nil, "", nil, 0, 0
}

// dayPast reports whether day is older than the server takes (the day
// before its own).
func dayPast(day string, now time.Time) bool {
	d, err := time.Parse(time.DateOnly, day)
	return err != nil || d.Before(now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -1))
}

// state loads the state, starting it on the first run: counting starts now
// (nothing from before telemetry existed), the first report a day or so
// after.
func (s *Sender) state() (State, error) {
	st, err := s.env.LoadState()
	if err != nil {
		return st, err
	}
	if st.FirstStart.IsZero() {
		now := s.env.Now()
		st.FirstStart = now
		st.AuditAfter = s.env.LatestAudit()
		st.NextAt = nextSlot(now)
		err = s.env.SaveState(st)
	}
	return st, err
}

// waiting says why no report may go yet: the user hasn't been told, and
// it's not been noticeGrace since the first start.
func (s *Sender) waiting(st State, now time.Time) string {
	if st.NoticeSeen.IsZero() && now.Sub(st.FirstStart) < noticeGrace {
		return "until you've been told about telemetry (the app's notice, or `riftroute telemetry`)"
	}
	return ""
}

// errRefused: the server answered, and didn't take the report.
var errRefused = errors.New("refused")

// post sends r: nil once the server took it, errRefused (wrapped) when it
// answered no.
func (s *Sender) post(ctx context.Context, r *Report) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.env.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "riftroute")
	resp, err := s.env.HTTP.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	resp.Body.Close()
	switch {
	case resp.StatusCode/100 == 2:
		return nil
	case resp.StatusCode/100 == 4 && resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusRequestTimeout:
		return fmt.Errorf("%w: server answered %s", errRefused, resp.Status)
	}
	return fmt.Errorf("server answered %s", resp.Status)
}

// build makes the report as it would go now, renewing the install id when
// it's due; snap is the counters it carries, last the newest audit id.
func (s *Sender) build(ctx context.Context, st *State, level domain.TelemetryLevel, now time.Time) (*Report, map[string]int, int64, error) {
	if st.Install == "" || now.Sub(st.InstallAt) >= installTTL || now.Before(st.InstallAt) {
		id, err := newInstall()
		if err != nil {
			return nil, nil, 0, err
		}
		st.Install, st.InstallAt = id, now
	}
	snap := s.env.Counters.Snapshot()
	in, last, err := s.env.Gather(ctx, level, st.AuditAfter)
	if err != nil {
		return nil, nil, 0, err
	}
	in.Level, in.Install, in.Now, in.Counts = level, st.Install, now, snap
	r := Build(in)
	if err := r.Validate(); err != nil {
		// A bug, never the user's data: nothing goes out.
		return nil, nil, 0, fmt.Errorf("report doesn't fit the schema: %w", err)
	}
	return r, snap, last, nil
}

// Preview is the report as it would be sent now, and the last one sent.
func (s *Sender) Preview(ctx context.Context) (Preview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	level := s.env.Level()
	p := Preview{Level: level}
	st, err := s.state()
	if err != nil {
		return p, err
	}
	p.NoticeSeen = !st.NoticeSeen.IsZero()
	if !st.LastSent.IsZero() {
		t := st.LastSent
		p.LastSent, p.Last = &t, st.LastReport
	}
	if level == domain.TelemetryOff {
		return p, nil
	}
	now := s.env.Now()
	next := st.NextAt
	p.NextAt = &next
	if pr := st.Pending; pr != nil && pr.Level == string(level) && !dayPast(pr.Day, now) {
		// What goes next is the report the server didn't answer, again.
		p.Next, p.Waiting = pr, "to send this report again (the server didn't answer)"
		return p, nil
	}
	p.Waiting = s.waiting(st, now)
	id := st.Install
	r, _, _, err := s.build(ctx, &st, level, now)
	if err != nil {
		return p, err
	}
	if st.Install != id {
		// Renewed now, so the id shown is the one that goes.
		_ = s.env.SaveState(st)
	}
	p.Next = r
	return p, nil
}

// MarkNoticeSeen records that the user has been told: reports may start.
func (s *Sender) MarkNoticeSeen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.state()
	if err != nil {
		return err
	}
	if !st.NoticeSeen.IsZero() {
		return nil
	}
	st.NoticeSeen = s.env.Now()
	return s.env.SaveState(st)
}

// NoticeDue reports whether the user should be told (telemetry is on and
// they haven't been). It doesn't wait for a report being sent: State asks.
func (s *Sender) NoticeDue() bool {
	if s.env.Level() == domain.TelemetryOff {
		return false
	}
	st, err := s.env.LoadState()
	return err == nil && st.NoticeSeen.IsZero()
}

// nextSlot is a random time in the next UTC day, so installs don't all
// report at once.
func nextSlot(now time.Time) time.Time {
	day := now.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	n, err := rand.Int(rand.Reader, big.NewInt(int64(24*time.Hour/time.Second)))
	if err != nil {
		return day.Add(12 * time.Hour)
	}
	return day.Add(time.Duration(n.Int64()) * time.Second)
}

func newInstall() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("no randomness for an install id")
	}
	return hex.EncodeToString(b[:]), nil
}
