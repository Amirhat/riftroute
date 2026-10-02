//go:build !darwin && !linux

package telemetry

func hostOS() (int, string) { return 0, "" }
