package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func panicCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "panic",
		Short: "Flush ALL RiftRoute-managed routes and restore baseline (idempotent)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := client().Panic(cmd.Context()); err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), map[string]string{"status": "panicked"})
			}
			fmt.Fprintln(cmd.OutOrStdout(), "panic complete — all managed routes removed, baseline restored")
			return nil
		},
	}
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
