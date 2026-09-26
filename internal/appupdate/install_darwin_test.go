//go:build darwin

package appupdate

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestTargetIsTheBundleTheAppRunsFrom(t *testing.T) {
	for exe, want := range map[string]string{
		"/Applications/RiftRoute.app/Contents/MacOS/RiftRoute":          "/Applications/RiftRoute.app",
		"/Users/me/Applications/RiftRoute.app/Contents/MacOS/RiftRoute": "/Users/me/Applications/RiftRoute.app",
		"/usr/local/bin/riftroute":                                      "", // not in a bundle
		"/tmp/build/bin/RiftRoute":                                      "",
	} {
		if got := Target(exe); got != want {
			t.Errorf("Target(%q) = %q, want %q", exe, got, want)
		}
	}
}

func TestCheckRefusesWhatThisUserCantReplace(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "RiftRoute.app")
	_ = os.MkdirAll(app, 0o755)
	if why := (MacInstaller{}).Check(app); why != "" {
		t.Fatalf("a writable bundle: %q", why)
	}
	if why := (MacInstaller{}).Check("/private/var/folders/x/AppTranslocation/y/d/RiftRoute.app"); why == "" {
		t.Fatal("a translocated copy passed")
	}
	if os.Geteuid() != 0 { // root may write anywhere
		_ = os.Chmod(dir, 0o555)
		defer os.Chmod(dir, 0o755)
		if why := (MacInstaller{}).Check(app); why == "" {
			t.Fatal("a bundle in a read-only folder passed")
		}
	}
	if why := (MacInstaller{}).Check(filepath.Join(dir, "missing.app")); why == "" {
		t.Fatal("a missing bundle passed")
	}
}

// The whole macOS install, end to end, on local stand-ins: a DMG with an
// ad-hoc signed bundle is mounted, checked, copied and swapped in; the
// previous app is kept, and Undo puts it back.
func TestMacInstallEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a disk image")
	}
	if _, err := exec.LookPath("hdiutil"); err != nil {
		t.Skip("no hdiutil")
	}
	dir := t.TempDir()
	mkBundle := func(path, id, version string) {
		t.Helper()
		_ = os.MkdirAll(filepath.Join(path, "Contents/MacOS"), 0o755)
		plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>` + id + `</string>
<key>CFBundleShortVersionString</key><string>` + version + `</string>
<key>CFBundleExecutable</key><string>RiftRoute</string>
</dict></plist>`
		_ = os.WriteFile(filepath.Join(path, "Contents/Info.plist"), []byte(plist), 0o644)
		_ = os.WriteFile(filepath.Join(path, "Contents/MacOS/RiftRoute"), []byte("#!/bin/sh\necho "+version+"\n"), 0o755)
		if out, err := exec.Command("codesign", "--force", "--sign", "-", path).CombinedOutput(); err != nil {
			t.Skipf("codesign: %v %s", err, out)
		}
	}
	src := filepath.Join(dir, "src")
	mkBundle(filepath.Join(src, "RiftRoute.app"), "com.test.RiftRoute", "0.2.8")
	dmg := filepath.Join(dir, "r.dmg")
	if out, err := exec.Command("hdiutil", "create", "-quiet", "-srcfolder", src, "-format", "UDZO", "-volname", "RiftRoute", dmg).CombinedOutput(); err != nil {
		t.Skipf("hdiutil create: %v %s", err, out)
	}
	apps := filepath.Join(dir, "Applications")
	target := filepath.Join(apps, "RiftRoute.app")
	mkBundle(target, "com.test.RiftRoute", "0.2.7")

	ctx := context.Background()
	if err := (MacInstaller{}).Install(ctx, dmg, target, "0.2.9"); err == nil {
		t.Fatal("installed an app that isn't the release's version")
	}
	if err := (MacInstaller{}).Install(ctx, dmg, target, "0.2.8"); err != nil {
		t.Fatal(err)
	}
	version := func(p string) string {
		v, _ := plistValue(ctx, p, "CFBundleShortVersionString")
		return v
	}
	if version(target) != "0.2.8" || version(macPrev(target)) != "0.2.7" {
		t.Fatalf("after install: %q, kept %q", version(target), version(macPrev(target)))
	}
	if err := (MacInstaller{}).Undo(target); err != nil {
		t.Fatal(err)
	}
	if version(target) != "0.2.7" {
		t.Fatalf("after undo: %q", version(target))
	}

	// Another app's disk image is refused.
	other := filepath.Join(dir, "other")
	mkBundle(filepath.Join(other, "RiftRoute.app"), "com.someone.Else", "0.2.8")
	odmg := filepath.Join(dir, "o.dmg")
	if out, err := exec.Command("hdiutil", "create", "-quiet", "-srcfolder", other, "-format", "UDZO", odmg).CombinedOutput(); err != nil {
		t.Skipf("hdiutil create: %v %s", err, out)
	}
	if err := (MacInstaller{}).Install(ctx, odmg, target, "0.2.8"); err == nil {
		t.Fatal("installed another app")
	}
}
