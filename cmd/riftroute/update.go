package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Amirhat/riftroute/internal/update"
)

func updateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Check GitHub Releases for a newer RiftRoute (does not self-install)",
		Long: "Checks the project's GitHub Releases for a newer version and reports it.\n" +
			"It never replaces a running binary: applying an update is a documented,\n" +
			"privileged, signature-verified step (see README).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
			if res.Notes != "" {
				fmt.Fprintf(out, "\n%s\n", res.Notes)
			}
			fmt.Fprintln(out, "\nApply: download the signed asset for your platform, verify its SHA-256\nagainst the release checksums, then reinstall (see README → Updating).")
			return nil
		},
	}
	return cmd
}
