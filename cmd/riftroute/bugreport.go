package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/Amirhat/riftroute/internal/bugreport"
	"github.com/Amirhat/riftroute/internal/buildinfo"
	"github.com/Amirhat/riftroute/internal/domain"
)

func bugreportCmd() *cobra.Command {
	var (
		out    string
		stdout bool
	)
	cmd := &cobra.Command{
		Use:   "bugreport",
		Short: "Write a redacted diagnostics report to attach to an issue",
		Long: "Collects versions, settings, profiles, routes, doctor results, recent\n" +
			"activity and the daemon log into a text file, with addresses, domains,\n" +
			"names and home paths replaced by placeholders. Nothing is uploaded:\n" +
			"review the file, then attach it to an issue yourself.\n\n" +
			"Works even when the daemon is down (with less detail); run with sudo to\n" +
			"include the daemon log in that case.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			rep := collectBugReport(ctx, bugreport.Client{Name: "riftroute CLI", Build: buildinfo.Current(version)})
			if stdout {
				fmt.Fprint(cmd.OutOrStdout(), rep.Text)
				return nil
			}
			if out == "" {
				out = "riftroute-bugreport-" + rep.GeneratedAt.Format("20060102-150405") + ".txt"
			}
			// 0600: even redacted, it's the user's to share, not other local users'.
			if err := os.WriteFile(out, []byte(rep.Text), 0o600); err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "wrote %s (%d values redacted)\n", out, rep.Redactions)
			fmt.Fprintf(w, "Review it before sharing, then attach it to a new issue:\n  %s\n", bugreport.IssueURL)
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "file to write (default riftroute-bugreport-<time>.txt)")
	cmd.Flags().BoolVar(&stdout, "stdout", false, "print the report instead of writing a file")
	return cmd
}

// collectBugReport asks the daemon for its report and adds the client's view;
// if the daemon doesn't answer, it builds the offline report instead.
func collectBugReport(ctx context.Context, c bugreport.Client) domain.BugReport {
	rep, err := client().BugReport(ctx)
	if err != nil {
		return bugreport.Offline(ctx, time.Now(), c, err)
	}
	var daemon *domain.Health
	if h, herr := client().Health(ctx); herr == nil {
		daemon = &h
	}
	return bugreport.WithClient(ctx, rep, c, daemon)
}
