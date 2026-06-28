// Command riftroute is the unprivileged CLI client. It talks to riftrouted over
// the UDS via the shared apiclient (spec §9). Every command supports --json;
// mutating commands (M2+) also support --dry-run and --yes. Exit codes are
// stable so scripts can branch.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/Amirhat/riftroute/internal/apiclient"
)

// Stable exit codes (spec §9).
const (
	exitOK                = 0
	exitError             = 1
	exitUsage             = 2
	exitDaemonUnreachable = 3
	exitGuardrail         = 4 // a guardrail refused the change (M2+)
	exitRolledBack        = 5 // apply failed but was rolled back (M2+)
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	err := rootCmd().Execute()
	os.Exit(exitCode(err))
}

func exitCode(err error) int {
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, apiclient.ErrDaemonUnreachable):
		fmt.Fprintln(os.Stderr, "error:", err)
		fmt.Fprintln(os.Stderr, "hint: is riftrouted running? try `riftroute daemon status` or start it with `riftrouted`.")
		return exitDaemonUnreachable
	case errors.Is(err, errUsage):
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsage
	case errors.Is(err, errGuardrail):
		return exitGuardrail // message already printed by the command
	case errors.Is(err, errRolledBack):
		return exitRolledBack
	default:
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
}

var (
	errUsage      = errors.New("usage error")
	errGuardrail  = errors.New("refused by guardrail")
	errRolledBack = errors.New("change rolled back")
)
