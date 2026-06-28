package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func flowsCmd() *cobra.Command {
	var vpnOnly bool
	cmd := &cobra.Command{
		Use:   "flows",
		Short: "List active connections and whether each goes via VPN or direct",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			flows, err := client().Flows(cmd.Context())
			if err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), flows)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "PROTO\tREMOTE\tIFACE\tPATH\tPROCESS")
			n := 0
			for _, f := range flows {
				if vpnOnly && !f.ViaVPN {
					continue
				}
				path := "direct"
				if f.ViaVPN {
					path = "via VPN"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", f.Proto, f.Remote, f.Iface, path, f.Process)
				n++
			}
			_ = tw.Flush()
			fmt.Fprintf(cmd.OutOrStdout(), "\n%d connection(s)\n", n)
			return nil
		},
	}
	cmd.Flags().BoolVar(&vpnOnly, "vpn", false, "only connections going via the VPN")
	return cmd
}
