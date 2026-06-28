// Package platform centralizes per-OS paths, privilege checks, and (later)
// service installation (launchd/systemd). It keeps OS specifics out of the rest
// of the codebase.
package platform

import (
	"os"
	"path/filepath"
	"runtime"
)

// Paths are the daemon's filesystem locations.
type Paths struct {
	// Socket is the UDS the API listens on.
	Socket string
	// DB is the SQLite database path.
	DB string
	// StateDir is the directory holding the DB and other daemon state.
	StateDir string
}

// IsPrivileged reports whether the process is running as root.
func IsPrivileged() bool { return os.Geteuid() == 0 }

// DefaultPaths returns production paths when running as root, and per-user dev
// paths otherwise (so M0 needs no root). Explicit flags override these.
func DefaultPaths() Paths {
	if IsPrivileged() {
		switch runtime.GOOS {
		case "darwin":
			dir := "/Library/Application Support/RiftRoute"
			return Paths{Socket: "/var/run/riftroute.sock", DB: filepath.Join(dir, "riftroute.db"), StateDir: dir}
		default: // linux + others
			return Paths{Socket: "/var/run/riftroute.sock", DB: "/var/lib/riftroute/riftroute.db", StateDir: "/var/lib/riftroute"}
		}
	}

	// Unprivileged / dev: keep the socket in the runtime dir and state under the
	// user's config dir.
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = os.TempDir()
	}
	cfg, err := os.UserConfigDir()
	if err != nil || cfg == "" {
		cfg = os.TempDir()
	}
	stateDir := filepath.Join(cfg, "riftroute")
	return Paths{
		Socket:   filepath.Join(runtimeDir, "riftroute.sock"),
		DB:       filepath.Join(stateDir, "riftroute-dev.db"),
		StateDir: stateDir,
	}
}
