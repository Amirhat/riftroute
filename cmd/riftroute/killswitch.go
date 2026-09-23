package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func killswitchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "killswitch",
		Short: "Keep your apps' traffic inside the VPN tunnel so it can't leak if the VPN drops",
		Long: "While on, processes of regular login accounts (your apps) reach the internet only\n" +
			"through a VPN tunnel, the LAN, or destinations your exclude profiles route around\n" +
			"the VPN. Root and system accounts are never blocked, so VPN clients' privileged\n" +
			"helpers can always reconnect; standard VPN ports stay open. System services\n" +
			"(including the OS resolver's DNS lookups) are not blocked. `riftroute panic`\n" +
			"turns it off.",
	}
	cmd.AddCommand(
		killswitchToggleCmd("on", true),
		killswitchToggleCmd("off", false),
		killswitchStatusCmd(),
	)
	return cmd
}

func killswitchToggleCmd(use string, on bool) *cobra.Command {
	short := "Disable the kill switch"
	if on {
		short = "Enable the kill switch"
	}
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			enabled, err := client().SetKillSwitch(cmd.Context(), on)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "kill switch: %s\n", onoff(enabled))
			return nil
		},
	}
}

func killswitchStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show kill switch status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := client().State(cmd.Context())
			if err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), map[string]bool{"kill_switch": st.KillSwitch})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "kill switch: %s\n", onoff(st.KillSwitch))
			return nil
		},
	}
}

func onoff(b bool) string {
	if b {
		return "ON"
	}
	return "off"
}
