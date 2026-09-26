package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/Amirhat/riftroute/internal/apiclient"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/update"
)

func updateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Show update status (verified, automatic updates of the daemon)",
		Long: "RiftRoute's daemon updates itself from signed releases: it verifies each\n" +
			"release's signature and checksum, tests the new version before switching,\n" +
			"installs only when nothing is in progress, and rolls back on its own if the\n" +
			"new version doesn't come up healthy. `riftroute update mode` chooses whether\n" +
			"it installs automatically, only tells you, or doesn't check at all.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := client().UpdateStatus(cmd.Context())
			if noUpdater(err) {
				return legacyCheck(cmd)
			}
			if err != nil {
				return err
			}
			return showUpdate(cmd, st)
		},
	}
	cmd.AddCommand(updateModeCmd(),
		&cobra.Command{
			Use: "check", Short: "Check for an update now", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				st, err := client().UpdateCheck(cmd.Context())
				if noUpdater(err) {
					return legacyCheck(cmd)
				}
				if err != nil {
					return err
				}
				return showUpdate(cmd, st)
			},
		},
		&cobra.Command{
			Use: "install", Short: "Install the available update (the daemon restarts at a quiet moment)", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				st, err := client().UpdateInstall(cmd.Context())
				if err != nil {
					return err
				}
				return showUpdate(cmd, st)
			},
		},
		&cobra.Command{
			Use: "rollback", Short: "Go back to the version the last update replaced", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				if err := client().UpdateRollback(cmd.Context()); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "rolling back — the daemon restarts into the previous version")
				return nil
			},
		},
	)
	return cmd
}

// noUpdater: a daemon from before automatic updates (no /update endpoint) or
// one running without an updater.
func noUpdater(err error) bool {
	var ae *apiclient.APIError
	return errors.As(err, &ae) && (ae.StatusCode == http.StatusNotFound || ae.StatusCode == http.StatusServiceUnavailable)
}

func showUpdate(cmd *cobra.Command, st domain.UpdateStatus) error {
	if g.json {
		return printJSON(cmd.OutOrStdout(), st)
	}
	printUpdate(cmd.OutOrStdout(), st, time.Now())
	return nil
}

func printUpdate(out io.Writer, st domain.UpdateStatus, now time.Time) {
	fmt.Fprintf(out, "RiftRoute %s — updates: %s\n", st.Current, st.Mode)
	if !st.LastCheck.IsZero() {
		src := ""
		if st.Source != "" {
			src = " (from " + map[string]string{"server": "the update server", "github": "GitHub"}[st.Source] + ")"
		}
		if st.Latest != "" {
			fmt.Fprintf(out, "latest: %s%s, checked %s ago\n", st.Latest, src, now.Sub(st.LastCheck).Round(time.Minute))
		} else {
			fmt.Fprintf(out, "checked %s ago\n", now.Sub(st.LastCheck).Round(time.Minute))
		}
	}
	switch {
	case st.Error != "":
		fmt.Fprintf(out, "problem: %s\n", st.Error)
	case st.State == "waiting" && st.Staged != "":
		fmt.Fprintf(out, "→ %s\n", st.Reason)
	case st.Reason != "":
		fmt.Fprintf(out, "→ %s\n", st.Reason)
	}
	if st.RolledBackFrom != "" {
		fmt.Fprintf(out, "%s was rolled back on this computer and won't be offered again.\n", st.RolledBackFrom)
	}
	if st.NotesURL != "" && st.Latest != st.Current {
		fmt.Fprintf(out, "release notes: %s\n", st.NotesURL)
	}
	if st.CanRollBack {
		fmt.Fprintln(out, "the previous version is kept: `riftroute update rollback` goes back to it")
	}
	if !st.SelfUpdatable && st.Action == string(update.ActionNotify) {
		fmt.Fprintln(out, "this install isn't updated automatically — update it the way you installed it")
	}
}

// legacyCheck is the pre-updater behaviour for daemons without /update: ask
// GitHub directly and report.
func legacyCheck(cmd *cobra.Command) error {
	res, err := update.Check(cmd.Context(), nil, "", version)
	if err != nil {
		return fmt.Errorf("update check failed: %w", err)
	}
	if g.json {
		return printJSON(cmd.OutOrStdout(), res)
	}
	out := cmd.OutOrStdout()
	if !res.Available {
		fmt.Fprintf(out, "up to date (%s; latest %s)\n", res.Current, res.Latest)
		return nil
	}
	fmt.Fprintf(out, "update available: %s → %s\n%s\n", res.Current, res.Latest, res.URL)
	fmt.Fprintln(out, "(this daemon predates automatic updates: install the new release, then its daemon)")
	return nil
}
