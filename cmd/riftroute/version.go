package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/Amirhat/riftroute/internal/buildinfo"
	"github.com/Amirhat/riftroute/internal/domain"
)

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print client (and, if reachable, daemon) version and build",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			self := buildinfo.Current(version)
			// Daemon info is best-effort; `version` never fails on an
			// unreachable daemon.
			h, herr := client().Health(cmd.Context())
			if g.json {
				// "client"/"daemon" stay version strings (scripts read them);
				// the build details ride alongside.
				out := map[string]any{"client": version, "client_build": self}
				if herr == nil {
					out["daemon"] = h.Version
					out["daemon_health"] = h
				}
				return printJSON(cmd.OutOrStdout(), out)
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "riftroute  %s\n", buildinfo.Short(self))
			if herr != nil {
				fmt.Fprintln(w, "riftrouted (not reachable)")
				return nil
			}
			fmt.Fprintf(w, "riftrouted %s\n", buildinfo.Short(h.Build))
			printBuildNotes(w, self, h)
			return nil
		},
	}
}

// printBuildNotes warns when the daemon is running something other than what
// is installed or what this client expects — the classic "I updated, but the
// fix doesn't work" trap.
func printBuildNotes(w io.Writer, self domain.BuildInfo, h domain.Health) {
	if h.RestartRequired {
		fmt.Fprintf(w, "\n! restart needed: %s\n  run: sudo riftroute daemon restart\n", h.RestartReason)
	}
	if m := buildinfo.Mismatch(self, h.Build); m != "" {
		fmt.Fprintf(w, "\n! %s\n", m)
	}
}
