package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/tunnel"
)

// A machine without openvpn says so up front — with this system's install
// steps — and a connect is refused as a precondition, not a server error.
func TestTunnelEngineReportsMissingOpenVPN(t *testing.T) {
	srv, ts, prov := newKillSwitchServer(t, nil)
	m, err := tunnel.New(tunnel.Options{
		Dir: t.TempDir(), Launcher: &tunnel.FakeLauncher{Missing: true}, Ifaces: prov.Interfaces,
		Apply: func(context.Context) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Shutdown)
	srv.SetTunnels(m)

	resp, err := http.Get(ts.URL + "/tunnels/engine")
	if err != nil {
		t.Fatal(err)
	}
	var e domain.TunnelEngine
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || e.Available || e.Problem != "OpenVPN isn't installed" || e.Install == nil || e.Install.System == "" {
		t.Fatalf("status %d, engine %+v", resp.StatusCode, e)
	}

	spec := `{"name":"infra","config":"client\nremote 192.0.2.1 1194\n<ca>\nCA\n</ca>\n","routes":["10.20.0.0/24"]}`
	post(t, ts.URL+"/tunnels", spec) // saving works without openvpn
	resp, err = http.Post(ts.URL+"/tunnels/infra/connect", "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatal(err)
	}
	var body struct{ Error string }
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionFailed || !strings.Contains(body.Error, "isn't installed") {
		t.Fatalf("connect: status %d, %q", resp.StatusCode, body.Error)
	}
}
