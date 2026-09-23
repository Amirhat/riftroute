//go:build darwin

package platform

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A socket file left by a killed daemon must not count as "came up" — only a
// listener accepting connections does.
func TestDialUntilIgnoresStaleSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "rr.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close() // leaves a stale socket file behind
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("sanity: stale socket file should exist: %v", err)
	}
	if err := dialUntil(sock, 300*time.Millisecond); err == nil {
		t.Fatal("stale socket reported as up")
	}
}

func TestDialUntilWaitsForListener(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "rr.sock")
	lnc := make(chan net.Listener, 1)
	go func() {
		time.Sleep(400 * time.Millisecond) // daemon still starting
		ln, err := net.Listen("unix", sock)
		if err != nil {
			t.Error(err)
		}
		lnc <- ln
	}()
	err := dialUntil(sock, 5*time.Second)
	if ln := <-lnc; ln != nil {
		_ = ln.Close()
	}
	if err != nil {
		t.Fatalf("listener came up but dialUntil failed: %v", err)
	}
}
