//go:build !darwin && !linux

package appupdate

// NewInstaller: the app updates itself only on macOS and as a Linux AppImage.
func NewInstaller() Installer { return nil }

// Target is unknown here.
func Target(string) string { return "" }
