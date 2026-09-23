package domain

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
