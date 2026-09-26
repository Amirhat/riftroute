//go:build !windows

package main

import (
	"strings"
	"testing"
)

// A second daemon on the same state directory is refused before it does
// anything; once the first is gone, the next one starts.
func TestLockInstanceAllowsOneDaemonPerStateDir(t *testing.T) {
	dir := t.TempDir()
	if err := lockInstance(dir); err != nil {
		t.Fatal(err)
	}
	first := instanceLock
	if err := lockInstance(dir); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second daemon: %v", err)
	}
	if err := lockInstance(t.TempDir()); err != nil {
		t.Fatalf("another state dir: %v", err)
	}
	_ = instanceLock.Close()
	_ = first.Close() // the first daemon exits
	if err := lockInstance(dir); err != nil {
		t.Fatalf("after the first exited: %v", err)
	}
	_ = instanceLock.Close()
}
