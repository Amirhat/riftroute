package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/Amirhat/riftroute/internal/apiclient"
	"github.com/Amirhat/riftroute/internal/killswitch"
)

func panicCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "panic",
		Short: "Flush ALL RiftRoute-managed routes, turn the kill switch off, and restore baseline (idempotent)",
		Long: "Flushes every RiftRoute-managed route and rule, turns the kill switch off, and\n" +
			"restores the baseline. If the daemon is down, run it with sudo: the kill switch\n" +
			"(which keeps holding while the service is stopped) is then removed directly.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := client().Panic(cmd.Context())
			if errors.Is(err, apiclient.ErrDaemonUnreachable) {
				return offlinePanic(cmd, err)
			}
			if err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), map[string]string{"status": "panicked"})
			}
			fmt.Fprintln(cmd.OutOrStdout(), "panic complete — all managed routes removed, kill switch off, baseline restored")
			return nil
		},
	}
}

// offlinePanic is the way out when the daemon can't be reached: the kill
// switch outlives the daemon by design, so as root remove it directly. Routes
// need the daemon's ownership records and are flushed on its next start.
func offlinePanic(cmd *cobra.Command, reachErr error) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("%w\nthe daemon is down; run `sudo riftroute panic` to remove the kill switch without it", reachErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := killswitch.New().Disable(ctx); err != nil {
		return fmt.Errorf("daemon unreachable, and removing the kill switch directly failed: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "daemon unreachable — removed the kill switch directly.\n"+
		"Start the daemon (sudo riftroute daemon start) and run panic again to flush managed routes.")
	return nil
}

func snapshotCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "snapshot", Short: "Snapshots of captured network state"}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List snapshots",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			snaps, err := client().Snapshots(cmd.Context())
			if err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), snaps)
			}
			if len(snaps) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no snapshots")
				return nil
			}
			for _, s := range snaps {
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %s  %s\n", s.ID, s.CreatedAt.Format("2006-01-02 15:04:05"), s.Reason)
			}
			return nil
		},
	})
	return cmd
}
