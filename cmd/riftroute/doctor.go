package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Amirhat/riftroute/internal/domain"
)

func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run a diagnostics battery (gateway, routes, DNS, drift, leaks)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rep, err := client().Doctor(cmd.Context())
			if err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), rep)
			}
			out := cmd.OutOrStdout()
			for _, c := range rep.Checks {
				fmt.Fprintf(out, "%s  %-16s %s\n", mark(c.Status), c.Name, c.Detail)
				if c.Fix != "" && c.Status != domain.CheckPass {
					fmt.Fprintf(out, "                     ↳ %s\n", c.Fix)
				}
			}
			fmt.Fprintf(out, "\n%d pass, %d warn, %d fail — %s\n", rep.Pass, rep.Warn, rep.Fail, overall(rep.OK))
			if !rep.OK {
				return errDoctorIssues // distinct non-zero exit; report already printed
			}
			return nil
		},
	}
}

func mark(s domain.CheckStatus) string {
	switch s {
	case domain.CheckPass:
		return "✓"
	case domain.CheckWarn:
		return "!"
	default:
		return "✗"
	}
}

func overall(ok bool) string {
	if ok {
		return "healthy"
	}
	return "ATTENTION NEEDED"
}
