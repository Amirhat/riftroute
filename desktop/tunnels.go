package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/Amirhat/riftroute/internal/apiclient"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/tunnel"
)

// TunnelProfileFile is an OpenVPN profile picked in the native dialog: the
// files it references are inlined here, as the desktop user (never by the
// root daemon), and it is parsed so the editor can preview what will run.
type TunnelProfileFile struct {
	Path      string   `json:"path"`
	Name      string   `json:"name"`
	Config    string   `json:"config"`
	Servers   []string `json:"servers"`
	NeedsAuth bool     `json:"needs_auth"`
	Ignored   []string `json:"ignored"`
	// Username/Password come from an auth-user-pass file or inline block.
	Username string `json:"username"`
	Password string `json:"password"`
	// Error is why the profile can't be used (shown inline; empty = usable).
	Error string `json:"error"`
}

// OpenTunnelProfileDialog picks a .ovpn file. An empty Path with a nil error
// means the user cancelled.
func (a *App) OpenTunnelProfileDialog() (TunnelProfileFile, error) {
	path, err := wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{
		Title: "Choose an OpenVPN profile",
		Filters: []wruntime.FileFilter{
			{DisplayName: "OpenVPN profile (*.ovpn, *.conf)", Pattern: "*.ovpn;*.conf"},
			{DisplayName: "All files", Pattern: "*"},
		},
	})
	if err != nil || path == "" {
		return TunnelProfileFile{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return TunnelProfileFile{}, fmt.Errorf("could not read %s: %w", filepath.Base(path), err)
	}
	out := TunnelProfileFile{Path: path, Name: filepath.Base(path), Servers: []string{}, Ignored: []string{}}
	text, creds, err := tunnel.InlineFiles(string(data), filepath.Dir(path), os.ReadFile)
	if err != nil {
		out.Error = err.Error()
		return out, nil
	}
	out.Config = text
	if creds != nil {
		out.Username, out.Password = creds.Username, creds.Password
	}
	p, err := tunnel.Parse(text)
	if err != nil {
		out.Error = err.Error()
		return out, nil
	}
	out.Servers, out.NeedsAuth = p.Servers(), p.NeedsAuth
	if p.Ignored != nil {
		out.Ignored = p.Ignored
	}
	if out.Username == "" {
		out.Username, out.Password = p.InlineUser, p.InlinePass
	}
	return out, nil
}

// GetTunnels lists the VPN connections RiftRoute runs itself.
func (a *App) GetTunnels() ([]domain.TunnelStatus, error) {
	ctx, cancel := a.call()
	defer cancel()
	ts, err := a.client.Tunnels(ctx)
	if ts == nil {
		ts = []domain.TunnelStatus{}
	}
	return ts, err
}

// SaveTunnel creates or updates a tunnel. Validation problems come back in
// the result's Issues, not as a thrown error.
func (a *App) SaveTunnel(spec domain.TunnelSpec) (apiclient.TunnelResult, error) {
	ctx, cancel := a.tunnelCall()
	defer cancel()
	res, err := a.client.SaveTunnel(ctx, spec)
	var ve *apiclient.ValidationError
	if errors.As(err, &ve) {
		return apiclient.TunnelResult{Issues: ve.Issues}, nil
	}
	return res, err
}

// DeleteTunnel disconnects and removes a tunnel.
func (a *App) DeleteTunnel(name string) error {
	ctx, cancel := a.tunnelCall()
	defer cancel()
	return a.client.DeleteTunnel(ctx, name)
}

// ConnectTunnel starts a tunnel; progress arrives with the state events.
func (a *App) ConnectTunnel(name string) (domain.TunnelStatus, error) {
	ctx, cancel := a.call()
	defer cancel()
	return a.client.ConnectTunnel(ctx, name)
}

// DisconnectTunnel stops a tunnel and waits for it to go down.
func (a *App) DisconnectTunnel(name string) (domain.TunnelStatus, error) {
	ctx, cancel := a.tunnelCall()
	defer cancel()
	return a.client.DisconnectTunnel(ctx, name)
}

// tunnelCall allows for a disconnect (a save can reconnect, a delete
// disconnects), which may wait out openvpn's shutdown.
func (a *App) tunnelCall() (context.Context, context.CancelFunc) {
	return context.WithTimeout(a.ctx, 20*time.Second)
}
