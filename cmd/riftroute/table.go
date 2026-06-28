package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/Amirhat/riftroute/internal/domain"
)

func tableCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "table",
		Short: "Inspect the kernel routing table",
	}
	cmd.AddCommand(tableShowCmd())
	return cmd
}

func tableShowCmd() *cobra.Command {
	var (
		managed bool
		system  bool
		v6      bool
	)
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the routing table (classified by owner)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			family := domain.FamilyV4
			if v6 {
				family = domain.FamilyV6
			}
			var owner domain.Owner
			switch {
			case managed:
				owner = domain.OwnerRiftRoute
			case system:
				owner = domain.OwnerSystem
			}
			routes, err := client().Routes(cmd.Context(), family, owner)
			if err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), routes)
			}
			renderRoutes(cmd, routes)
			return nil
		},
	}
	cmd.Flags().BoolVar(&managed, "managed", false, "only RiftRoute-owned routes")
	cmd.Flags().BoolVar(&system, "system", false, "only system routes")
	cmd.Flags().BoolVarP(&v6, "6", "6", false, "show IPv6 instead of IPv4")
	return cmd
}

func renderRoutes(cmd *cobra.Command, routes []domain.Route) {
	if len(routes) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "no routes")
		return
	}
	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "DESTINATION\tGATEWAY\tINTERFACE\tMETRIC\tOWNER")
	for _, r := range routes {
		gw := r.Gateway
		if gw == "" {
			gw = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", r.DstCIDR, gw, r.Iface, r.Metric, r.Owner)
	}
	_ = tw.Flush()
	fmt.Fprintf(cmd.OutOrStdout(), "\n%d route(s)\n", len(routes))
}
