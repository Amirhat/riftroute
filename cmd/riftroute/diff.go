package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func diffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff",
		Short: "Show the desired-vs-actual difference over managed routes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := client().Diff(cmd.Context())
			if err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), d)
			}
			out := cmd.OutOrStdout()
			if d.InSync {
				fmt.Fprintln(out, "in sync — desired matches actual")
				return nil
			}
			fmt.Fprintf(out, "%d to add, %d to remove, %d to change:\n", d.Adds, d.Dels, d.Changes)
			for _, e := range d.Entries {
				sign := map[string]string{"add": "+", "del": "-", "change": "~"}[string(e.Action)]
				fmt.Fprintf(out, "  %s %s via %s dev %s\n", sign, e.Route.DstCIDR, e.Route.Gateway, e.Route.Iface)
			}
			return nil
		},
	}
}
