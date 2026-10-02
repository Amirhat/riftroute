package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/telemetry"
)

var updateModeHelp = map[domain.UpdateMode]string{
	domain.UpdateAuto:   "install verified updates automatically when idle, rolling back if the new version misbehaves",
	domain.UpdateNotify: "check for updates and tell you; installing is your choice",
	domain.UpdateOff:    "never check on its own (`riftroute update` still checks when you run it)",
}

var telemetryHelp = map[domain.TelemetryLevel]string{
	domain.TelemetryFull:  "basic, plus anonymous feature-usage counts and error codes",
	domain.TelemetryBasic: "version, OS/architecture, and update/crash outcomes only",
	domain.TelemetryOff:   "send nothing — no telemetry request is ever made",
}

// telemetryPromise is printed with every telemetry view: the hard limits
// hold at every level.
const telemetryPromise = "Never sent at any level: IP addresses or networks, domains, profile/list/app/\n" +
	"user/tunnel names, network or host names, or anything you typed. Off sends\n" +
	"nothing at all — no request is made."

// telemetryNotice is told once, where the app would show its notice: the
// first `status` or `doctor` on a terminal.
const telemetryNotice = "RiftRoute sends an anonymous report once a day, to catch a broken release\n" +
	"early: version and platform, update and crash outcomes, and (at \"full\", the\n" +
	"default) counts of what's configured and of how changes and tunnels went.\n" +
	telemetryPromise + "\n" +
	"  See the exact report:  riftroute telemetry show\n" +
	"  Send less, or nothing: riftroute telemetry basic | off"

// stdoutTerminal reports whether w is a terminal: a person reads it. Tests
// stand in for one.
var stdoutTerminal = func(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// tellAboutTelemetry prints the notice when it's due, to a person (never
// into --json or a pipe), and records that it was seen.
func tellAboutTelemetry(ctx context.Context, w io.Writer, due bool) {
	if !due || g.json || !stdoutTerminal(w) {
		return
	}
	fmt.Fprintf(w, "\n%s\n", telemetryNotice)
	_ = client().TelemetryNoticeSeen(ctx)
}

func updateModeCmd() *cobra.Command {
	return &cobra.Command{
		Use:       "mode [auto|notify|off]",
		Short:     "Show or set what RiftRoute does about new releases",
		Args:      cobra.MaximumNArgs(1),
		ValidArgs: []string{"auto", "notify", "off"},
		RunE: func(cmd *cobra.Command, args []string) error {
			var p domain.Preferences
			var err error
			if len(args) == 0 {
				p, err = client().Preferences(cmd.Context())
			} else {
				m := domain.UpdateMode(args[0])
				if !m.Valid() {
					return fmt.Errorf("unknown update mode %q (want auto, notify, or off)", args[0])
				}
				p, err = client().SetPreferences(cmd.Context(), domain.PreferencesPatch{Updates: &m})
			}
			if err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), p)
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "updates: %s — %s\n", p.Updates, updateModeHelp[p.Updates])
			return nil
		},
	}
}

func telemetryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "telemetry [full|basic|off|show]",
		Short: "Show or set how much anonymous usage data RiftRoute sends",
		Long: "Show or set the telemetry level; `show` prints the exact report that would\n" +
			"be sent now, and the last one sent.\n\n" + telemetryPromise,
		Args:      cobra.MaximumNArgs(1),
		ValidArgs: []string{"full", "basic", "off", "show"},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, c := cmd.Context(), client()
			if len(args) == 1 && args[0] == "show" {
				_ = c.TelemetryNoticeSeen(ctx) // they're looking at it
				p, err := c.TelemetryPreview(ctx)
				if err != nil {
					return err
				}
				return renderTelemetryPreview(cmd.OutOrStdout(), p)
			}
			var p domain.Preferences
			var err error
			if len(args) == 0 {
				p, err = c.Preferences(ctx)
			} else {
				l := domain.TelemetryLevel(args[0])
				if !l.Valid() {
					return fmt.Errorf("unknown telemetry level %q (want full, basic, or off)", args[0])
				}
				p, err = c.SetPreferences(ctx, domain.PreferencesPatch{Telemetry: &l})
			}
			if err != nil {
				return err
			}
			_ = c.TelemetryNoticeSeen(ctx) // told (and maybe chose)
			if g.json {
				return printJSON(cmd.OutOrStdout(), p)
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "telemetry: %s — %s\n", p.Telemetry, telemetryHelp[p.Telemetry])
			if pv, err := c.TelemetryPreview(ctx); err == nil {
				renderTelemetrySchedule(w, pv)
			}
			fmt.Fprintf(w, "\n%s\n", telemetryPromise)
			return nil
		},
	}
}

// renderTelemetrySchedule says when the next report goes, and the last went.
func renderTelemetrySchedule(w io.Writer, p telemetry.Preview) {
	switch {
	case p.Level == domain.TelemetryOff:
	case p.Waiting != "":
		fmt.Fprintf(w, "  next report: waiting %s\n", p.Waiting)
	case p.NextAt != nil:
		fmt.Fprintf(w, "  next report: around %s\n", p.NextAt.Local().Format("2006-01-02 15:04"))
	}
	if p.LastSent != nil {
		fmt.Fprintf(w, "  last sent:   %s\n", p.LastSent.Local().Format("2006-01-02 15:04"))
	} else {
		fmt.Fprintln(w, "  last sent:   never")
	}
}

// renderTelemetryPreview is `telemetry show`: the reports as JSON.
func renderTelemetryPreview(w io.Writer, p telemetry.Preview) error {
	if g.json {
		return printJSON(w, p)
	}
	fmt.Fprintf(w, "telemetry: %s\n", p.Level)
	renderTelemetrySchedule(w, p)
	if p.Next == nil {
		fmt.Fprintln(w, "\nNothing is sent while telemetry is off.")
	} else {
		fmt.Fprintln(w, "\nThe report as it would be sent now (indented here):")
		if err := printJSON(w, p.Next); err != nil {
			return err
		}
	}
	if p.Last != nil {
		fmt.Fprintln(w, "\nThe last report sent:")
		return printJSON(w, p.Last)
	}
	return nil
}

// renderPreferences is the one-line summary `status` prints.
func renderPreferences(w io.Writer, p domain.Preferences) {
	fmt.Fprintf(w, "  Updates:       %s · Telemetry: %s\n", p.Updates, p.Telemetry)
}
