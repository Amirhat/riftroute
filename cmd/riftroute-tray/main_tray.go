//go:build tray && (darwin || linux)

// Command riftroute-tray is the menu-bar / system-tray companion (spec §3.2/§15):
// a tiny unprivileged process that talks to riftrouted over the UDS and offers
// quick toggles — kill switch, profile enable/disable, Panic, and opening the
// GUI. It is built separately (cgo + native tray libs) and excluded from the
// cgo-free core build via the `tray` build tag.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"time"

	"fyne.io/systray"

	"github.com/Amirhat/riftroute/internal/apiclient"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/platform"
)

var socketFlag = flag.String("socket", "", "riftrouted socket path (default: platform client socket)")

func main() {
	flag.Parse()
	sock := *socketFlag
	if sock == "" {
		sock = platform.ClientSocket()
	}
	t := &tray{cl: apiclient.New(sock)}
	systray.Run(t.onReady, func() {})
}

type tray struct {
	cl       *apiclient.Client
	mStatus  *systray.MenuItem
	mVPN     *systray.MenuItem
	mKill    *systray.MenuItem
	mProfile map[string]*systray.MenuItem
	mPanic   *systray.MenuItem
	mOpen    *systray.MenuItem
	mQuit    *systray.MenuItem
}

func (t *tray) onReady() {
	systray.SetTitle("RR")
	systray.SetTooltip("RiftRoute")
	t.mStatus = systray.AddMenuItem("Connecting…", "")
	t.mStatus.Disable()
	t.mVPN = systray.AddMenuItem("VPN: —", "")
	t.mVPN.Disable()
	systray.AddSeparator()
	t.mKill = systray.AddMenuItemCheckbox("Kill switch", "Fence all egress to the tunnel", false)
	systray.AddSeparator()
	t.mProfile = map[string]*systray.MenuItem{}
	t.mPanic = systray.AddMenuItem("Panic — flush all routes", "Remove every managed route immediately")
	systray.AddSeparator()
	t.mOpen = systray.AddMenuItem("Open RiftRoute…", "Open the desktop app")
	t.mQuit = systray.AddMenuItem("Quit tray", "Quit this menu-bar helper")

	go t.loop()
}

func (t *tray) loop() {
	t.refresh()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.refresh()
		case <-t.mKill.ClickedCh:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			cur := t.mKill.Checked()
			_, _ = t.cl.SetKillSwitch(ctx, !cur)
			cancel()
			t.refresh()
		case <-t.mPanic.ClickedCh:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = t.cl.Panic(ctx)
			cancel()
			t.refresh()
		case <-t.mOpen.ClickedCh:
			openApp()
		case <-t.mQuit.ClickedCh:
			systray.Quit()
			return
		}
	}
}

func (t *tray) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	st, err := t.cl.State(ctx)
	if err != nil {
		t.mStatus.SetTitle("daemon unreachable")
		systray.SetTitle("RR!")
		return
	}
	drift := "in sync"
	if st.Drift.Pending {
		drift = "drift pending"
	}
	t.mStatus.SetTitle(fmt.Sprintf("%s · %s · %d routes", st.Health.Daemon, drift, st.ManagedRouteCount))
	if st.VPN.Active {
		t.mVPN.SetTitle("VPN: up")
		systray.SetTitle("RR")
	} else {
		t.mVPN.SetTitle("VPN: down")
		systray.SetTitle("RR·")
	}
	if st.KillSwitch {
		t.mKill.Check()
	} else {
		t.mKill.Uncheck()
	}
	t.syncProfiles(st.Profiles)
}

// syncProfiles adds a checkbox per profile on first sight and keeps each in sync;
// clicking toggles enable/disable with an immediate apply.
func (t *tray) syncProfiles(profiles []domain.ProfileStatus) {
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })
	for _, p := range profiles {
		mi, ok := t.mProfile[p.Name]
		if !ok {
			mi = systray.AddMenuItemCheckbox("Profile: "+p.Name, "Toggle and apply", p.Enabled)
			t.mProfile[p.Name] = mi
			name := p.Name
			go func() {
				for range mi.ClickedCh {
					ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
					_, _ = t.cl.SetProfileEnabled(ctx, name, !mi.Checked(), true)
					cancel()
					t.refresh()
				}
			}()
		}
		if p.Enabled {
			mi.Check()
		} else {
			mi.Uncheck()
		}
	}
}

func openApp() {
	switch runtime.GOOS {
	case "darwin":
		_ = exec.Command("open", "-a", "RiftRoute").Start()
	case "linux":
		_ = exec.Command("riftroute-gui").Start() // best-effort; on PATH after install
	default:
		fmt.Fprintln(os.Stderr, "open not supported on this platform")
	}
}
