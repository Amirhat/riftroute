package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Amirhat/riftroute/internal/platform"
)

func daemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Manage the riftrouted system service (launchd/systemd)",
	}
	cmd.AddCommand(daemonStatusCmd(), daemonInstallCmd(), daemonUninstallCmd(), daemonRestartCmd())
	return cmd
}

func daemonStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether the daemon service is installed, loaded, and reachable",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc := platform.NewServiceManager().Status()
			version, perr := client().Ping(cmd.Context())
			reachable := perr == nil
			if g.json {
				return printJSON(cmd.OutOrStdout(), map[string]any{
					"service":   svc,
					"reachable": reachable,
					"version":   version,
				})
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Service manager: %s\n", svc.Manager)
			fmt.Fprintf(out, "  installed: %s\n", yesno(svc.Installed))
			fmt.Fprintf(out, "  loaded:    %s\n", yesno(svc.Loaded))
			if reachable {
				fmt.Fprintf(out, "  API:       reachable (riftrouted %s)\n", version)
			} else {
				fmt.Fprintf(out, "  API:       not reachable\n")
			}
			if !svc.Installed {
				fmt.Fprintln(out, "\nInstall with: sudo riftroute daemon install")
			}
			return nil
		},
	}
}

func daemonInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install and start riftrouted as a system service (requires root)",
		Long: "Installs the riftrouted binary to /usr/local/bin, writes the launchd\n" +
			"plist / systemd unit, and starts it. Run with sudo.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			bin, err := platform.FindDaemonBinary()
			if err != nil {
				return err
			}
			socket := platform.SystemSocket()
			if err := platform.NewServiceManager().Install(bin, socket); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "installed and started riftrouted (socket %s)\n", socket)
			fmt.Fprintln(cmd.OutOrStdout(), "verify with: riftroute daemon status")
			return nil
		},
	}
}

func daemonUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Stop and remove the riftrouted system service (requires root)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := platform.NewServiceManager().Uninstall(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "uninstalled riftrouted")
			return nil
		},
	}
}

func daemonRestartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restart",
		Short: "Restart the riftrouted system service (requires root)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := platform.NewServiceManager().Restart(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "restarted riftrouted")
			return nil
		},
	}
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
