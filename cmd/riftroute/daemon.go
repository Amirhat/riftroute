package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/Amirhat/riftroute/internal/buildinfo"
	"github.com/Amirhat/riftroute/internal/platform"
)

func daemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Manage the riftrouted system service (launchd/systemd)",
	}
	cmd.AddCommand(daemonStatusCmd(), daemonInstallCmd(), daemonUninstallCmd(),
		daemonRestartCmd(), daemonStartCmd(), daemonStopCmd())
	return cmd
}

func daemonStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether the daemon service is installed, loaded, and reachable",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc := platform.NewServiceManager().Status()
			h, perr := client().Health(cmd.Context())
			reachable := perr == nil
			if g.json {
				out := map[string]any{
					"service":   svc,
					"reachable": reachable,
					"version":   h.Version,
				}
				if reachable {
					out["health"] = h
				}
				return printJSON(cmd.OutOrStdout(), out)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Service manager: %s\n", svc.Manager)
			fmt.Fprintf(out, "  installed: %s\n", yesno(svc.Installed))
			if svc.Loaded && svc.Detail != "" {
				fmt.Fprintf(out, "  loaded:    yes (%s)\n", svc.Detail)
			} else {
				fmt.Fprintf(out, "  loaded:    %s\n", yesno(svc.Loaded))
			}
			if reachable {
				fmt.Fprintf(out, "  API:       reachable (riftrouted %s)\n", buildinfo.Short(h.Build))
				if h.Binary != "" {
					fmt.Fprintf(out, "  binary:    %s\n", h.Binary)
				}
				if !h.StartedAt.IsZero() {
					fmt.Fprintf(out, "  started:   %s\n", h.StartedAt.Local().Format("2006-01-02 15:04:05"))
				}
				printBuildNotes(out, buildinfo.Current(version), h)
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
	var (
		allowUID       int
		allowDowngrade bool
	)
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install and start riftrouted as a system service (requires root)",
		Long: "Installs the riftrouted binary (macOS: /Library/PrivilegedHelperTools,\n" +
			"Linux: /usr/local/bin), writes the launchd plist / systemd unit, and\n" +
			"(re)starts it. Run with sudo.\n\n" +
			"The daemon runs as root but authorizes --allow-uid (default: the invoking\n" +
			"user, even under sudo) for mutating calls, so an unprivileged GUI/CLI can\n" +
			"control it.\n\n" +
			"Installing a build older than the one already installed is refused unless\n" +
			"--allow-downgrade is given; afterwards the running daemon is checked to be\n" +
			"the build that was installed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			bin, err := platform.FindDaemonBinary()
			if err != nil {
				return err
			}
			candidate, cerr := buildinfo.ReadFile(bin)
			if cerr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: %v (cannot check for a downgrade)\n", cerr)
			}
			if dst := platform.InstalledDaemonPath(); dst != "" && cerr == nil {
				if current, err := buildinfo.ReadFile(dst); err == nil {
					if err := guardDowngrade(candidate, current, bin, allowDowngrade); err != nil {
						return err
					}
					fmt.Fprintf(out, "replacing riftrouted %s\n", buildinfo.Short(current))
				}
			}
			fmt.Fprintf(out, "installing riftrouted %s\n  from %s\n", buildinfo.Short(candidate), bin)
			if allowUID < 0 {
				allowUID = invokingUID()
			}
			socket := platform.SystemSocket()
			if err := platform.NewServiceManager().Install(bin, socket, allowUID); err != nil {
				return err
			}
			if cerr == nil {
				if err := verifyRunning(cmd.Context(), candidate, client().Health); err != nil {
					return err
				}
			}
			fmt.Fprintf(out, "installed and started riftrouted %s (socket %s, allow-uid %d)\n",
				buildinfo.Short(candidate), socket, allowUID)
			return nil
		},
	}
	cmd.Flags().IntVar(&allowUID, "allow-uid", -1, "uid allowed to control the daemon (default: invoking user)")
	cmd.Flags().BoolVar(&allowDowngrade, "allow-downgrade", false, "install even if the binary is older than the installed daemon")
	return cmd
}

// invokingUID returns the real user behind a privileged invocation: SUDO_UID if
// present (run via sudo), else the current uid.
func invokingUID() int {
	if s := os.Getenv("SUDO_UID"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			return n
		}
	}
	return os.Getuid()
}

func daemonUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Flush managed routes, then stop and remove the riftrouted service (requires root)",
		Long: "Restores the host to its pre-RiftRoute state: flushes ALL managed routes/\n" +
			"rules while the daemon is still alive (its ownership DB is the source of\n" +
			"truth on macOS), then unloads and removes the service and binary.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Flush first, while the daemon is up. The reconciler is event-driven, so
			// nothing re-applies between the flush and the unload below.
			ctx, cancel := context.WithTimeout(cmd.Context(), 8*time.Second)
			flushErr := client().Panic(ctx)
			cancel()
			if flushErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"warning: could not flush managed routes (daemon may be down): %v\n"+
						"if any RiftRoute routes remain, start the daemon and run `riftroute panic`.\n", flushErr)
			}
			if err := platform.NewServiceManager().Uninstall(); err != nil {
				return err
			}
			if flushErr == nil {
				fmt.Fprintln(cmd.OutOrStdout(), "flushed managed routes and uninstalled riftrouted")
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "uninstalled riftrouted")
			}
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
			// Confirm the restarted daemon runs what is installed on disk.
			if want, err := buildinfo.ReadFile(platform.InstalledDaemonPath()); err == nil {
				if err := verifyRunning(cmd.Context(), want, client().Health); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "restarted riftrouted %s\n", buildinfo.Short(want))
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout(), "restarted riftrouted")
			return nil
		},
	}
}

func daemonStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start the installed riftrouted service (requires root)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := platform.NewServiceManager().Start(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "started riftrouted")
			return nil
		},
	}
}

func daemonStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the running riftrouted service without removing it (requires root)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := platform.NewServiceManager().Stop(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "stopped riftrouted")
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
