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

// systemSocket is where the installed (root) daemon listens.
const systemSocket = "/var/run/riftroute.sock"

// ClientSocket resolves the socket an unprivileged client (CLI/GUI) should dial:
// an explicit RIFTROUTE_SOCKET override, else the installed system socket when
// present, else the per-user dev socket. This lets the GUI/CLI reach a
// root-installed daemon while still working in same-user dev mode (spec §4.4
// note; resolves the M0 dev-vs-prod path mismatch).
func ClientSocket() string {
	if s := os.Getenv("RIFTROUTE_SOCKET"); s != "" {
		return s
	}
	if _, err := os.Stat(systemSocket); err == nil {
		return systemSocket
	}
	return DefaultPaths().Socket
}

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
