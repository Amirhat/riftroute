package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/Amirhat/riftroute/internal/domain"
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

// telemetryPromise is printed with every telemetry view: the hard limits hold
// at every level, and this version sends nothing yet.
const telemetryPromise = "Never sent at any level: IP addresses, domains, profile/list/app/user names,\n" +
	"network or host names. This version does not send telemetry yet — the level\n" +
	"you choose now is what future versions will respect."

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
			if p.Updates == domain.UpdateAuto {
				fmt.Fprintln(w, "(automatic install arrives in an upcoming version; until then you are notified)")
			}
			return nil
		},
	}
}

func telemetryCmd() *cobra.Command {
	return &cobra.Command{
		Use:       "telemetry [full|basic|off]",
		Short:     "Show or set how much anonymous usage data RiftRoute may send",
		Long:      "Show or set the telemetry level.\n\n" + telemetryPromise,
		Args:      cobra.MaximumNArgs(1),
		ValidArgs: []string{"full", "basic", "off"},
		RunE: func(cmd *cobra.Command, args []string) error {
			var p domain.Preferences
			var err error
			if len(args) == 0 {
				p, err = client().Preferences(cmd.Context())
			} else {
				l := domain.TelemetryLevel(args[0])
				if !l.Valid() {
					return fmt.Errorf("unknown telemetry level %q (want full, basic, or off)", args[0])
				}
				p, err = client().SetPreferences(cmd.Context(), domain.PreferencesPatch{Telemetry: &l})
			}
			if err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), p)
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "telemetry: %s — %s\n\n%s\n", p.Telemetry, telemetryHelp[p.Telemetry], telemetryPromise)
			return nil
		},
	}
}

// renderPreferences is the one-line summary `status` prints.
func renderPreferences(w io.Writer, p domain.Preferences) {
	fmt.Fprintf(w, "  Updates:       %s · Telemetry: %s\n", p.Updates, p.Telemetry)
}
