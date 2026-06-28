package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Amirhat/riftroute/internal/apiclient"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/safety"
)

func applyCmd() *cobra.Command {
	var (
		dryRun bool
		yes    bool
	)
	cmd := &cobra.Command{
		Use:   "apply [file]",
		Short: "Reconcile live routing to the enabled profiles (or a config file)",
		Long: "With no file, reconciles to the currently enabled profiles.\n" +
			"With a file (default ./riftroute.yaml if present), validates and applies it.\n" +
			"Without --yes, applies interactively with commit-confirm.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			file := ""
			if len(args) == 1 {
				file = args[0]
			} else if _, err := os.Stat("riftroute.yaml"); err == nil {
				file = "riftroute.yaml"
			}
			if file != "" {
				return applyFile(cmd, file, dryRun, yes)
			}
			return applyCurrent(cmd, dryRun, yes)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the plan + inverse, change nothing")
	cmd.Flags().BoolVar(&yes, "yes", false, "non-interactive: skip the keep-changes prompt (guard still runs)")
	return cmd
}

func applyFile(cmd *cobra.Command, file string, dryRun, yes bool) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	format := "yaml"
	if strings.HasSuffix(file, ".toml") {
		format = "toml"
	}
	res, err := client().ApplyConfig(cmd.Context(), data, format, dryRun, yes)
	// Render validation issues regardless of error.
	for _, is := range res.Issues {
		loc := ""
		if is.Line > 0 {
			loc = fmt.Sprintf("line %d: ", is.Line)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s%s\n", is.Severity, loc, is.Msg)
	}
	if err != nil {
		return fmt.Errorf("config rejected (%s)", file)
	}
	if g.json {
		return printJSON(cmd.OutOrStdout(), res)
	}
	if res.Plan != nil { // dry-run
		renderPlan(cmd, *res.Plan)
		return nil
	}
	if res.Result != nil {
		return renderApplyResult(cmd, *res.Result, yes)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "config applied")
	return nil
}

func applyCurrent(cmd *cobra.Command, dryRun, yes bool) error {
	if dryRun {
		plan, _, err := client().Plan(cmd.Context())
		if err != nil {
			return err
		}
		if g.json {
			return printJSON(cmd.OutOrStdout(), plan)
		}
		renderPlan(cmd, plan)
		return nil
	}
	res, err := client().Apply(cmd.Context(), apiclient.ApplyOptions{Yes: yes})
	if err != nil {
		return err
	}
	if g.json {
		return printJSON(cmd.OutOrStdout(), res)
	}
	return renderApplyResult(cmd, res, yes)
}

func renderPlan(cmd *cobra.Command, plan domain.Plan) {
	out := cmd.OutOrStdout()
	if len(plan.Ops) == 0 {
		fmt.Fprintln(out, "in sync — no changes")
		return
	}
	fmt.Fprintf(out, "plan (%d op(s)):\n", len(plan.Ops))
	for _, op := range plan.Ops {
		fmt.Fprintf(out, "  %s\t# %s\n", op.Human, strings.Join(op.Command, " "))
	}
	fmt.Fprintln(out, "inverse (rollback):")
	for _, op := range plan.Inverse {
		fmt.Fprintf(out, "  %s\n", op.Human)
	}
}

// renderApplyResult prints the outcome and, for an interactive pending tx,
// prompts the user to keep or revert (commit-confirm). Returns a sentinel error
// for guardrail refusals / rollbacks so the process exit code is stable.
func renderApplyResult(cmd *cobra.Command, res safety.Result, yes bool) error {
	out := cmd.OutOrStdout()
	if len(res.Violations) > 0 {
		fmt.Fprintln(out, "refused by guardrails:")
		for _, v := range res.Violations {
			fmt.Fprintf(out, "  - %s: %s\n", v.Rule, v.Detail)
		}
		return errGuardrail
	}
	switch res.Status {
	case domain.TxCommitted:
		fmt.Fprintln(out, "applied — in sync (no changes needed)")
		return nil
	case domain.TxFailed:
		fmt.Fprintf(out, "apply failed (rolled back): %s\n", res.Error)
		return errRolledBack
	case domain.TxPending:
		fmt.Fprintf(out, "applied %d change(s) (tx %s)\n", res.Diff.Adds+res.Diff.Dels, res.TxID)
		if res.NeedsConfirm && !yes {
			return confirmPrompt(cmd, res.TxID)
		}
		fmt.Fprintln(out, "connectivity guard active; will auto-revert if connectivity drops")
		return nil
	default:
		return nil
	}
}

func confirmPrompt(cmd *cobra.Command, txID string) error {
	fmt.Fprint(cmd.OutOrStdout(), "Keep changes? [y/N] ")
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	if strings.EqualFold(strings.TrimSpace(line), "y") {
		result, err := client().Confirm(cmd.Context(), txID)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "kept (%s)\n", result)
		return nil
	}
	result, err := client().Rollback(cmd.Context(), txID)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "reverted (%s)\n", result)
	return errRolledBack
}
