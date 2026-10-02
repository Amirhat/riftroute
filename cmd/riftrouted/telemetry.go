package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/killswitch"
	"github.com/Amirhat/riftroute/internal/platform"
	"github.com/Amirhat/riftroute/internal/store"
	"github.com/Amirhat/riftroute/internal/telemetry"
	"github.com/Amirhat/riftroute/internal/tunnel"
)

// counts are the anonymous report's counters (docs/telemetry.md). Set once
// in run, before any loop starts; a nil one counts nothing.
var counts *telemetry.Counters

// telemetryStateKey is the setting the sender keeps its state in.
const telemetryStateKey = "telemetry_state"

// runMarker is there while the daemon runs: found at a start, the previous
// run didn't shut down (a crash, a kill, a power loss, a start that failed).
func runMarker(dir string) string { return filepath.Join(dir, "riftrouted.running") }

// openCounters loads the counters kept beside the database and counts this
// start (and an unclean end of the last run).
func openCounters(st *store.Store, dir string) *telemetry.Counters {
	p, _ := st.LoadPreferences()
	c := telemetry.OpenCounters(dir, p.Telemetry != domain.TelemetryOff)
	marker := runMarker(dir)
	if _, err := os.Stat(marker); err == nil {
		c.Inc(telemetry.KeyUnclean)
	}
	_ = os.WriteFile(marker, nil, 0o600)
	c.Inc(telemetry.KeyStarts)
	return c
}

// telemetryDeps are what a report is gathered from.
type telemetryDeps struct {
	st        *store.Store
	tunnels   *tunnel.Manager
	ks        killswitch.Manager
	autoApply func() bool
	app       telemetry.App
}

// newSender builds the daemon's report sender.
func newSender(d telemetryDeps, url string, logger *slog.Logger) *telemetry.Sender {
	return telemetry.NewSender(telemetry.Env{
		URL:      url,
		HTTP:     &http.Client{Timeout: time.Minute},
		Counters: counts,
		Level: func() domain.TelemetryLevel {
			p, err := d.st.LoadPreferences()
			if err != nil {
				return domain.TelemetryOff // unreadable: send nothing
			}
			return p.Telemetry
		},
		LoadState: func() (telemetry.State, error) {
			var s telemetry.State
			v, ok, err := d.st.GetSetting(telemetryStateKey)
			if err != nil || !ok {
				return s, err
			}
			if json.Unmarshal([]byte(v), &s) != nil {
				return telemetry.State{}, nil // unreadable: start over
			}
			return s, nil
		},
		SaveState: func(s telemetry.State) error {
			b, err := json.Marshal(s)
			if err != nil {
				return err
			}
			return d.st.SetSetting(telemetryStateKey, string(b))
		},
		Gather: d.gather,
		LatestAudit: func() int64 {
			id, _ := d.st.LatestAuditID()
			return id
		},
		Log: logger,
	})
}

// gather reads the daemon's records for a report: at basic only the app;
// at full, also what's configured and the audit events since auditAfter.
func (d telemetryDeps) gather(ctx context.Context, level domain.TelemetryLevel, auditAfter int64) (telemetry.Inputs, int64, error) {
	in := telemetry.Inputs{App: d.app}
	if level != domain.TelemetryFull {
		// Nothing read past what's sent; the audit counted from now on.
		id, err := d.st.LatestAuditID()
		return in, id, err
	}
	var err error
	if in.Profiles, err = d.st.ListProfiles(); err != nil {
		return in, auditAfter, err
	}
	if in.Lists, err = d.st.ListLists(); err != nil {
		return in, auditAfter, err
	}
	if routes, err := d.st.LoadSplitDNS(); err == nil {
		in.SplitDNS = len(routes) > 0
	}
	if d.tunnels != nil {
		in.Tunnels = d.tunnels.List()
	}
	if d.ks != nil {
		in.KillSwitch, _ = d.ks.Enabled(ctx)
	}
	in.AutoApply = d.autoApply()
	audit, last, err := d.st.AuditAfter(auditAfter, 0)
	if err != nil {
		return in, auditAfter, err
	}
	in.Audit = audit
	return in, last, nil
}

// installedService: this daemon is the installed system service.
func installedService(exe string) bool {
	return platform.IsPrivileged() && exe != "" && exe == platform.InstalledDaemonPath()
}
