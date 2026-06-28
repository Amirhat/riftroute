package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func profileCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "profile", Short: "Manage routing profiles"}
	cmd.AddCommand(profileListCmd(), profileShowCmd(), profileToggleCmd(true), profileToggleCmd(false))
	return cmd
}

func profileListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List profiles",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			profs, err := client().Profiles(cmd.Context())
			if err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), profs)
			}
			if len(profs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no profiles (add some via `riftroute apply file.yaml`)")
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tENABLED\tMODE\tGATEWAY\tRULES")
			for _, p := range profs {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\n", p.Name, yn(p.Enabled), p.Mode, p.Gateway, len(p.Rules))
			}
			return tw.Flush()
		},
	}
}

func profileShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show a profile's rules",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profs, err := client().Profiles(cmd.Context())
			if err != nil {
				return err
			}
			for _, p := range profs {
				if p.Name != args[0] {
					continue
				}
				if g.json {
					return printJSON(cmd.OutOrStdout(), p)
				}
				out := cmd.OutOrStdout()
				fmt.Fprintf(out, "%s (enabled=%s mode=%s gateway=%s priority=%d)\n", p.Name, yn(p.Enabled), p.Mode, p.Gateway, p.Priority)
				for _, r := range p.Rules {
					fmt.Fprintf(out, "  - %s %s\t%s\n", r.Type, r.Value, r.Comment)
				}
				return nil
			}
			return fmt.Errorf("profile %q not found", args[0])
		},
	}
}

func profileToggleCmd(enable bool) *cobra.Command {
	use := "disable <name>"
	short := "Disable a profile and reconcile"
	if enable {
		use, short = "enable <name>", "Enable a profile and reconcile"
	}
	var yes bool
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := client().SetProfileEnabled(cmd.Context(), args[0], enable)
			if err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), res)
			}
			verb := "disabled"
			if enable {
				verb = "enabled"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %q\n", verb, args[0])
			return renderApplyResult(cmd, res, true) // toggle reconciles non-interactively
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "(reserved) non-interactive")
	return cmd
}
