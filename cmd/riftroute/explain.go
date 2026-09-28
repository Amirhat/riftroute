package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Amirhat/riftroute/internal/domain"
)

func routeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "route",
		Short: "Route inspection",
	}
	cmd.AddCommand(explainCmd())
	return cmd
}

func explainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "explain <ip|domain>",
		Short: "Show where traffic to a target goes, and why (kernel + simulated)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ex, err := client().Explain(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), ex)
			}
			renderExplain(cmd, ex)
			return nil
		},
	}
}

func renderExplain(cmd *cobra.Command, ex domain.RouteExplain) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Target: %s\n", ex.Target)
	if len(ex.Resolved) > 0 {
		fmt.Fprintf(out, "Resolved: %v\n", ex.Resolved)
	}
	renderDecision(cmd, "kernel", ex.Kernel)
	if ex.Simulated != nil {
		renderDecision(cmd, "simulated", *ex.Simulated)
		if ex.Drift {
			fmt.Fprintln(out, "  ⚠ DRIFT: kernel and desired disagree — reconcile pending")
		}
	}
	if ex.Note != "" {
		fmt.Fprintf(out, "Note: %s\n", ex.Note)
	}
}

func renderDecision(cmd *cobra.Command, label string, d domain.RouteDecision) {
	out := cmd.OutOrStdout()
	matched := d.MatchedCIDR
	if matched != "" {
		matched = " matches " + matched
	}
	switch {
	case d.Rejected && d.Tunnel != "":
		fmt.Fprintf(out, "  [%s]%s → blocked: tunnel %s is down (it's set to block when down)\n", label, matched, d.Tunnel)
		return
	case d.Rejected:
		fmt.Fprintf(out, "  [%s]%s → blocked (a reject route refuses it)\n", label, matched)
		return
	case !d.Reachable:
		fmt.Fprintf(out, "  [%s] unreachable (no matching route)\n", label)
		return
	}
	verdict := "DIRECT"
	switch {
	case d.Tunnel != "" && d.TunnelType != "":
		verdict = "via tunnel " + d.Tunnel + " (" + string(d.TunnelType) + ")"
	case d.Tunnel != "":
		verdict = "via tunnel " + d.Tunnel
	case d.ViaVPN:
		verdict = "via VPN"
	}
	gw := d.Gateway
	if gw == "" {
		gw = "on-link"
	}
	fmt.Fprintf(out, "  [%s]%s → via %s dev %s — %s\n", label, matched, gw, d.Iface, verdict)
}
