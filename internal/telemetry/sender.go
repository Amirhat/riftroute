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
	now := s.env.Now()
	if !on {
		// Off: nothing counted; when it's back on, it counts from then.
		if st.AuditAfter != s.env.LatestAudit() {
			st.AuditAfter = s.env.LatestAudit()
			_ = s.env.SaveState(st)
		}
		return
	}
	if now.Before(st.NextAt) {
		return
	}
	if why := s.waiting(st, now); why != "" {
		st.NextAt = nextSlot(now)
		_ = s.env.SaveState(st)
		return
	}
	if err := s.send(ctx, &st, level, now); err != nil {
		s.env.Log.Info("telemetry report not sent; trying again tomorrow", "err", err)
	}
	st.NextAt = nextSlot(now)
	_ = s.env.SaveState(st)
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

// send builds the report and posts it; on success the counters lose what
// it carried, and it's kept as the last one sent.
func (s *Sender) send(ctx context.Context, st *State, level domain.TelemetryLevel, now time.Time) error {
	r, snap, last, err := s.build(ctx, st, level, now)
	if err != nil {
		return err
	}
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
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("server answered %s", resp.Status)
	}
	s.env.Counters.Subtract(snap)
	_ = s.env.Counters.Flush()
	st.AuditAfter, st.LastSent, st.LastReport = last, now, r
	s.env.Log.Info("telemetry report sent", "level", level, "day", r.Day)
	return nil
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
