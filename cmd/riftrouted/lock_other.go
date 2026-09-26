//go:build windows

package main

// lockInstance: the daemon doesn't run on Windows (no provider).
func lockInstance(string) error { return nil }
