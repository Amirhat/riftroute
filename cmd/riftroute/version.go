package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print client (and, if reachable, daemon) version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Daemon version is best-effort; `version` never fails on an
			// unreachable daemon.
			daemonVer, _ := client().Ping(cmd.Context())
			if g.json {
				out := map[string]string{"client": version}
				if daemonVer != "" {
					out["daemon"] = daemonVer
				}
				return printJSON(cmd.OutOrStdout(), out)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "riftroute %s\n", version)
			if daemonVer != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "riftrouted %s\n", daemonVer)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "riftrouted (not reachable)")
			}
			return nil
		},
	}
}
