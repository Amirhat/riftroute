package tunnel

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
)

// One unreadable definition must not stop the daemon: the others load, and
// the broken one is reported by name.
func TestStoreSkipsBrokenDefinitions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tunnels")
	s, err := openDefStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.put(&def{Name: "good", Type: domain.TunnelOpenVPN, Config: "client\nremote 192.0.2.1\n"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte(`{"name": "bad", "config": `), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "dir.json"), 0o700); err != nil { // not a file at all
		t.Fatal(err)
	}

	defs, broken, err := s.scan()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(defs) != 1 || defs[0].Name != "good" {
		t.Errorf("defs = %+v, want just good", defs)
	}
	if len(broken) != 2 || broken["bad"] == nil || broken["dir"] == nil {
		t.Errorf("broken = %v, want bad and dir", broken)
	}

	defs, err = s.list()
	if err != nil || len(defs) != 1 || defs[0].Name != "good" {
		t.Errorf("list = %+v, %v; want just good", defs, err)
	}
}

func TestStoreScanFailsOnlyForTheDirectory(t *testing.T) {
	s := &defStore{dir: filepath.Join(t.TempDir(), "missing")}
	if _, _, err := s.scan(); err == nil {
		t.Fatal("an unreadable directory must be an error")
	}
}
