//go:build darwin

package updater

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

// wrongArch is the start of a Mach-O executable for a CPU no Mac runs
// (PowerPC 64): exec refuses it with EBADARCH.
func wrongArch() []byte {
	b := make([]byte, 4096)
	binary.LittleEndian.PutUint32(b[0:], 0xfeedfacf)    // MH_MAGIC_64
	binary.LittleEndian.PutUint32(b[4:], 18|0x01000000) // CPU_TYPE_POWERPC64
	binary.LittleEndian.PutUint32(b[12:], 2)            // MH_EXECUTE
	return b
}

// macOS says "bad CPU type" (EBADARCH), not ENOEXEC, for a binary built for
// another architecture; that and a malformed executable are the release's
// fault.
func TestWrongArchitectureIsBroken(t *testing.T) {
	ctx := context.Background()
	var b errBroken
	for _, errno := range []syscall.Errno{syscall.EBADARCH, syscall.EBADEXEC, syscall.EBADMACHO, syscall.ENOEXEC} {
		if !errors.As(classifyRun(ctx, &os.PathError{Op: "fork/exec", Path: "x", Err: errno}), &b) {
			t.Errorf("errno %d (%v) not classed as a broken release", int(errno), errno)
		}
	}
	// A cancelled run is never the release's fault, whatever the error.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if errors.As(classifyRun(cancelled, &os.PathError{Op: "fork/exec", Path: "x", Err: syscall.EBADARCH}), &b) {
		t.Error("a cancelled run classed as broken")
	}
}

// A release whose openvpn is for another architecture is skipped — not
// downloaded again at every check.
func TestReleaseWithAWrongArchitectureOpenVPNIsSkipped(t *testing.T) {
	f := newFakeRelease(t, "0.2.7", fakeDaemon("0.2.7"))
	f.tgz = macRelease(t, "0.2.7", wrongArch())
	h := newHarness(t, f, "0.2.6")
	ovpn := withOpenVPN(t, h, fakeOpenVPN("old"))
	st := h.check()
	if st.Staged != "" || !strings.Contains(st.Error, "bad CPU type") || h.restarts.Load() != 0 {
		t.Fatalf("wrong-arch openvpn: %+v", st)
	}
	if ps, _ := loadPersisted(h.env.StateDir); ps.Skip != "0.2.7" {
		t.Fatal("a release with a wrong-architecture openvpn wasn't skipped")
	}
	h.check()
	if n := f.downloads.Load(); n != 1 {
		t.Fatalf("downloaded %d times", n)
	}
	if !fileIs(t, ovpn, fakeOpenVPN("old")) {
		t.Fatal("openvpn touched")
	}
}

// The same for the repair: a wrong-architecture openvpn is tried once.
func TestRepairGivesUpOnAWrongArchitectureOpenVPN(t *testing.T) {
	f := newFakeRelease(t, "0.3.0", fakeDaemon("0.3.0"))
	f.tgz = macRelease(t, "0.3.0", wrongArch())
	h := newHarness(t, f, "0.3.0")
	ovpn := withOpenVPN(t, h, nil)
	h.check()
	h.check()
	if fileExists(ovpn) {
		t.Fatal("a wrong-architecture openvpn was installed")
	}
	if n := f.downloads.Load(); n != 1 {
		t.Fatalf("downloaded %d times", n)
	}
}
