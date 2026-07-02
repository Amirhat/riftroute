package main

import (
	"strings"
	"testing"
)

func TestElevateCmdDarwin(t *testing.T) {
	cli := "/Applications/RiftRoute.app/Contents/Resources/bin/riftroute"
	name, args, err := elevateCmd("darwin", cli, "install", "--allow-uid 501")
	if err != nil {
		t.Fatal(err)
	}
	if name != "osascript" || len(args) != 2 || args[0] != "-e" {
		t.Fatalf("got name=%q args=%v", name, args)
	}
	s := args[1]
	for _, want := range []string{
		"do shell script ",
		"with administrator privileges",
		"daemon install --allow-uid 501",
		`\"` + cli + `\"`,                // the CLI path is quoted inside the AppleScript string
		"xattr -dr com.apple.quarantine", // de-quarantine the bundled CLIs first
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script missing %q:\n%s", want, s)
		}
	}
}

func TestElevateCmdLinux(t *testing.T) {
	name, args, err := elevateCmd("linux", "/usr/bin/riftroute", "restart", "")
	if err != nil {
		t.Fatal(err)
	}
	if name != "pkexec" {
		t.Fatalf("name = %q, want pkexec", name)
	}
	if strings.Join(args, " ") != "/usr/bin/riftroute daemon restart" {
		t.Fatalf("args = %v", args)
	}
}

func TestElevateCmdUnsupported(t *testing.T) {
	if _, _, err := elevateCmd("windows", "x", "install", ""); err == nil {
		t.Fatal("expected error on unsupported OS")
	}
}
