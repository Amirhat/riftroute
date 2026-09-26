//go:build darwin

package updater

import "syscall"

// notExecutable are the exec errors that mean a file is no program this Mac
// can run: the release is broken, not this moment. macOS answers a binary
// for another architecture with EBADARCH ("bad CPU type in executable"), not
// ENOEXEC — without it, a wrong-architecture daemon or openvpn would be
// downloaded again at every check.
var notExecutable = []error{
	syscall.ENOEXEC,   // not an executable format at all
	syscall.EBADARCH,  // built for another CPU
	syscall.EBADEXEC,  // a malformed executable
	syscall.EBADMACHO, // a malformed Mach-O file
}
