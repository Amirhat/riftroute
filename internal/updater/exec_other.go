//go:build !darwin

package updater

import "syscall"

// notExecutable are the exec errors that mean a file is no program this
// machine can run (a binary for another architecture or format): the release
// is broken, not this moment.
var notExecutable = []error{syscall.ENOEXEC}
