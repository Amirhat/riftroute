package domain

import "time"

// UpdateMode is what RiftRoute may do about new releases on its own.
type UpdateMode string

const (
	// UpdateAuto installs verified updates when idle, with automatic rollback.
	UpdateAuto UpdateMode = "auto"
	// UpdateNotify checks and tells the user; installing is their click.
	UpdateNotify UpdateMode = "notify"
	// UpdateOff never checks on its own (a manual check still works).
	UpdateOff UpdateMode = "off"
)

// Valid reports whether m is a known mode.
func (m UpdateMode) Valid() bool {
	return m == UpdateAuto || m == UpdateNotify || m == UpdateOff
}

// TelemetryLevel is how much anonymous usage data RiftRoute may send. No level
// ever includes addresses, domains, or names of any kind.
type TelemetryLevel string

const (
	// TelemetryFull adds anonymous feature-usage counts and error codes.
	TelemetryFull TelemetryLevel = "full"
	// TelemetryBasic is version, platform, and update/crash outcomes only.
	TelemetryBasic TelemetryLevel = "basic"
	// TelemetryOff sends nothing — no telemetry request is ever made.
	TelemetryOff TelemetryLevel = "off"
)

// Valid reports whether l is a known level.
func (l TelemetryLevel) Valid() bool {
	return l == TelemetryFull || l == TelemetryBasic || l == TelemetryOff
}

// SettingKillSwitchNotice is the settings key holding State.KillSwitchNotice.
const SettingKillSwitchNotice = "kill_switch_notice"

// Preferences are the user's choices about what RiftRoute does over the
// network on its own. Each is one switch away from off.
type Preferences struct {
	Updates   UpdateMode     `json:"updates"`
	Telemetry TelemetryLevel `json:"telemetry"`
}

// DefaultPreferences applies when the user hasn't chosen.
func DefaultPreferences() Preferences {
	return Preferences{Updates: UpdateAuto, Telemetry: TelemetryFull}
}

// PreferencesPatch changes only the fields that are set.
type PreferencesPatch struct {
	Updates   *UpdateMode     `json:"updates,omitempty"`
	Telemetry *TelemetryLevel `json:"telemetry,omitempty"`
}

// UpdateStatus is what the daemon's updater knows (GET /update, and State).
type UpdateStatus struct {
	Mode    UpdateMode `json:"mode"`
	Current string     `json:"current"`
	// State: "idle", "checking", "downloading", "waiting" (staged, waiting for
	// a quiet moment), "installing", "error".
	State     string    `json:"state"`
	LastCheck time.Time `json:"last_check,omitzero"`
	Latest    string    `json:"latest,omitempty"`
	Source    string    `json:"source,omitempty"` // "server" | "github"
	// Action: "none", "hold", "notify", "install" — with Reason in words.
	Action   string `json:"action,omitempty"`
	Reason   string `json:"reason,omitempty"`
	NotesURL string `json:"notes_url,omitempty"`
	Error    string `json:"error,omitempty"`
	// Staged is a verified, self-tested version waiting to be installed.
	Staged string `json:"staged,omitempty"`
	// RolledBackFrom is a version that failed its health check here and was
	// rolled back automatically; it won't be offered again.
	RolledBackFrom string `json:"rolled_back_from,omitempty"`
	// RolledBackBy: "health" (it didn't start properly) or "you".
	RolledBackBy string    `json:"rolled_back_by,omitempty"`
	InstalledAt  time.Time `json:"installed_at,omitzero"`
	// CanRollBack: a previous binary is kept and can be restored.
	CanRollBack bool `json:"can_roll_back"`
	// SelfUpdatable is false for package-managed or non-service installs.
	SelfUpdatable bool `json:"self_updatable"`
}
