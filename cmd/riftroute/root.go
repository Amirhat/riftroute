package main

import (
	"encoding/json"
	"io"

	"github.com/spf13/cobra"

	"github.com/Amirhat/riftroute/internal/apiclient"
	"github.com/Amirhat/riftroute/internal/platform"
)

// printJSON writes v as indented JSON — the stable machine-readable form used by
// every `--json` command (spec §9/§16).
func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// globals holds flags shared by all commands.
type globals struct {
	socket string
	json   bool
}

var g globals

// client builds an apiclient pointed at the configured socket.
func client() *apiclient.Client {
	sock := g.socket
	if sock == "" {
		sock = platform.DefaultPaths().Socket
	}
	return apiclient.New(sock)
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "riftroute",
		Short: "RiftRoute — split-tunneling / policy-based routing controller",
		Long: "RiftRoute controls which destinations bypass (or use) your VPN, safely.\n" +
			"This CLI is an unprivileged client of the riftrouted daemon.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&g.socket, "socket", "", "riftrouted socket path (default: platform-specific)")
	root.PersistentFlags().BoolVar(&g.json, "json", false, "output machine-readable JSON")

	root.AddCommand(statusCmd())
	root.AddCommand(versionCmd())
	return root
}
