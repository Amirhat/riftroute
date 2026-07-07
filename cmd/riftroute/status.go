package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Amirhat/riftroute/internal/domain"
)

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show VPN, default-route owner, profiles, drift, and daemon health",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := client().State(cmd.Context())
			if err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), st)
			}
			renderStatus(cmd.OutOrStdout(), st)
			return nil
		},
	}
}

func renderStatus(w io.Writer, st domain.State) {
	h := st.Health
	fmt.Fprintln(w, "RiftRoute status")
	daemon := string(h.Daemon)
	if h.Reason != "" {
		daemon += " (" + h.Reason + ")"
	}
	fmt.Fprintf(w, "  Daemon:        %s — version %s, provider %s, pid %d, up %ds\n",
		daemon, h.Version, h.Provider, h.PID, h.UptimeSeconds)

	if st.VPN.Active {
		fmt.Fprintf(w, "  VPN:           active — %s\n", strings.Join(st.VPN.Interfaces, ", "))
	} else {
		fmt.Fprintln(w, "  VPN:           inactive")
	}

	fmt.Fprintln(w, "  Default route:")
	for _, d := range st.Defaults {
		if !d.Present {
			fmt.Fprintf(w, "    %s: (none)\n", d.Family)
			continue
		}
		via := "direct"
		if d.ViaVPN {
			via = "via VPN"
		}
		gw := d.Gateway
		if gw == "" {
			gw = "on-link"
		}
		fmt.Fprintf(w, "    %s: %s dev %s [%s] → %s\n", d.Family, gw, d.Iface, d.Owner, via)
	}

	if len(st.DNS.Servers) > 0 {
		fmt.Fprintf(w, "  DNS:           %s", strings.Join(st.DNS.Servers, ", "))
		if st.DNS.Iface != "" {
			fmt.Fprintf(w, " (%s)", st.DNS.Iface)
		}
		fmt.Fprintln(w)
	}

	up := 0
	parts := make([]string, 0, len(st.Interfaces))
	for _, ifc := range st.Interfaces {
		if ifc.Up {
			up++
		}
		tag := ""
		if ifc.IsVPN {
			tag = " [vpn]"
		}
		state := "down"
		if ifc.Up {
			state = "up"
		}
		parts = append(parts, fmt.Sprintf("%s %s%s", ifc.Name, state, tag))
	}
	fmt.Fprintf(w, "  Interfaces:    %d (%d up) — %s\n", len(st.Interfaces), up, strings.Join(parts, ", "))

	enabled := 0
	for _, p := range st.Profiles {
		if p.Enabled {
			enabled++
		}
	}
	fmt.Fprintf(w, "  Profiles:      %d enabled / %d total\n", enabled, len(st.Profiles))

	if st.Drift.Pending {
		fmt.Fprintf(w, "  Drift:         PENDING (+%d -%d) — run `riftroute diff`\n", st.Drift.Adds, st.Drift.Dels)
	} else {
		fmt.Fprintln(w, "  Drift:         none")
	}
	fmt.Fprintf(w, "  Managed:       %d route(s), %d rule(s)\n", st.ManagedRouteCount, st.ManagedRuleCount)

	c := st.Capabilities
	fmt.Fprintf(w, "  Capabilities:  platform=%s policy-routing=%s per-app=%s proto-tag=%s ipv6=%s\n",
		c.Platform, yn(c.PolicyRouting), yn(c.PerAppRouting), yn(c.ProtoTag), yn(c.IPv6))
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
