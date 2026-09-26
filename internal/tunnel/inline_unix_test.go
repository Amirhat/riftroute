//go:build unix

package tunnel

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Opening a FIFO for reading blocks until a writer appears: a profile naming
// one used to hang the CLI or the app for good.
func TestImportNeverOpensAFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	for name, read := range map[string]func() error{
		"InlineFiles": func() error {
			_, err := InlineFiles("client\nremote 192.0.2.1\nca pipe\n", dir)
			return err
		},
		"ReadProfileFile": func() error {
			_, err := ReadProfileFile(fifo)
			return err
		},
	} {
		done := make(chan error, 1)
		go func() { done <- read() }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Errorf("%s: got %v, want it refused as not a regular file", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s blocked opening a FIFO", name)
		}
	}
}
