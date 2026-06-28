package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func listCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "list", Short: "Manage reusable rule lists (static + remote)"}
	cmd.AddCommand(listListCmd(), listRefreshCmd())
	return cmd
}

func listListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show configured lists",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ls, err := client().Lists(cmd.Context())
			if err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), ls)
			}
			if len(ls) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no lists")
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tKIND\tENTRIES\tSOURCE")
			for _, l := range ls {
				kind := "static"
				if l.Source != "" {
					kind = "remote"
				}
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", l.Name, kind, len(l.Entries()), l.Source)
			}
			return tw.Flush()
		},
	}
}

func listRefreshCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "refresh [name]",
		Short: "Fetch remote list(s) and update the cache",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if all || len(args) == 0 {
				n, err := client().RefreshAllLists(cmd.Context())
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "refreshed %d remote list(s)\n", n)
				return nil
			}
			l, err := client().RefreshList(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), l)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "refreshed %q: %d entries (checksum %s)\n", l.Name, len(l.Entries()), short(l.Checksum))
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "refresh all remote lists")
	return cmd
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
