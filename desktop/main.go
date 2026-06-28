// Command desktop is the RiftRoute Wails GUI: a thin, unprivileged client of
// riftrouted. Wails owns the native window, menu, dialogs, tray, single-instance
// handling, and packaging (AGENTS §0/§1/§3). The Go side here holds the UDS
// connection to the daemon and re-emits updates to the React layer as Wails
// runtime events; React never speaks HTTP/SSE/sockets directly (spec §3.5).
//
// Lifecycle note (spec §3.1): closing this GUI does NOT stop routing —
// riftrouted is persistent and runs independently.
package main

import (
	"embed"
	"runtime"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/menu"
	"github.com/wailsapp/wails/v2/pkg/menu/keys"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
)

//go:embed all:frontend/dist
var assets embed.FS

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:     "RiftRoute",
		Width:     1200,
		Height:    820,
		MinWidth:  980,
		MinHeight: 640,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		// Matches the dark theme base so there's no white flash before the UI
		// paints (the React layer owns the real theme via CSS variables).
		BackgroundColour: &options.RGBA{R: 15, G: 18, B: 23, A: 1},
		Menu:             buildMenu(app),
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId:               "com.riftroute.desktop",
			OnSecondInstanceLaunch: app.onSecondInstance,
		},
		Bind: []interface{}{app},
		Mac: &mac.Options{
			TitleBar: mac.TitleBarHiddenInset(),
			About: &mac.AboutInfo{
				Title:   "RiftRoute",
				Message: "Split-tunneling / policy-based routing controller\nversion " + version,
			},
		},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}

// buildMenu wires a native menu that bridges to existing UI actions rather than
// reimplementing logic (AGENTS §3). The standard Edit menu is included so
// ⌘C/⌘V/Select-All work inside the webview's text inputs.
func buildMenu(app *App) *menu.Menu {
	m := menu.NewMenu()
	if runtime.GOOS == "darwin" {
		m.Append(menu.AppMenu())
	}
	m.Append(menu.EditMenu())

	view := m.AddSubmenu("View")
	view.AddText("Dashboard", keys.CmdOrCtrl("1"), func(_ *menu.CallbackData) { app.emit("rr:menu", "nav:dashboard") })
	view.AddText("Routing Table", keys.CmdOrCtrl("2"), func(_ *menu.CallbackData) { app.emit("rr:menu", "nav:routes") })
	view.AddText("Explain", keys.CmdOrCtrl("3"), func(_ *menu.CallbackData) { app.emit("rr:menu", "nav:explain") })
	view.AddSeparator()
	view.AddText("Refresh", keys.CmdOrCtrl("r"), func(_ *menu.CallbackData) { app.emit("rr:menu", "refresh") })
	view.AddText("Toggle Theme", keys.Combo("t", keys.CmdOrCtrlKey, keys.ShiftKey), func(_ *menu.CallbackData) { app.emit("rr:menu", "toggle-theme") })

	return m
}
