package telemetry

import "golang.org/x/sys/unix"

// hostOS is macOS's major version (15 for 15.6.1).
func hostOS() (int, string) {
	v, err := unix.Sysctl("kern.osproductversion")
	if err != nil {
		return 0, ""
	}
	return majorOf(v), ""
}
