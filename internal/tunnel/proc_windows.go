//go:build windows

package tunnel

import (
	"errors"
	"os/exec"
)

// Windows is out of scope for v1 (spec §1.4); these keep the package
// compiling there. Launchers find no openvpn, so nothing reaches them.

func ownProcessGroup(*exec.Cmd) {}

func terminate(int) error { return errors.New("not supported on windows") }

func alive(int) bool { return false }
