package telemetry

import "os"

// hostOS is the distribution's VERSION_ID's major number and its ID.
func hostOS() (int, string) {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if data, err := os.ReadFile(p); err == nil {
			id, major := osRelease(data)
			return major, id
		}
	}
	return 0, ""
}
