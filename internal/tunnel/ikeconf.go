package tunnel

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

// ikeFile is one file a charon-cmd session reads, written 0600 into the
// tunnel's run directory (0700) before it starts and removed when it ends.
type ikeFile struct {
	Name string
	Data []byte
}

// ikeSetup is everything one charon-cmd session is started with.
type ikeSetup struct {
	// Files: its strongswan.conf, the login certificate and key, and the
	// CAs to trust the server with.
	Files []ikeFile
	// Args are charon-cmd's arguments; Conf is the config file to name in
	// STRONGSWAN_CONF, and Socket the VICI socket it listens on.
	Args         []string
	Conf, Socket string
}

// ikePlugins are what a session loads: IKEv2 with userspace ESP over a TUN
// (kernel-libipsec) — the interface the tunnel's routes go into — the OS's
// routing (addresses only: charon-cmd installs no routes), VICI (how the
// daemon follows it), keys and certificates, EAP-MSCHAPv2. No DNS plugin,
// so the server's DNS is never applied; no updown, no attr. A name ending
// in ! must load or the session fails (a missing one is left out).
func ikePlugins(goos string) string {
	net := "kernel-netlink"
	if goos == "darwin" {
		net = "kernel-pfroute"
	}
	return strings.Join([]string{
		"random", "nonce", "openssl", "kdf", "pem", "pkcs1", "pkcs8", "x509", "pubkey", "constraints",
		"md4", "des", "eap-identity", "eap-mschapv2",
		"kernel-libipsec!", net + "!", "socket-default!", "vici!",
	}, " ")
}

// renderIKE lays out one session of the IKEv2 connection c to host (the
// server's address, pinned, or its name) for tunnel name, in dir. roots are
// the CAs to trust the server with when the profile carries none (the
// system's). v6 asks the server for IPv6 too (the tunnel routes some).
func renderIKE(c *IKEv2Config, roots []*x509.Certificate, host, dir, name string, v6 bool) (ikeSetup, error) {
	if c.Auth != IKEv2Certificate {
		// charon-cmd asks for an EAP password or a shared secret on a
		// terminal; the daemon has none to answer from.
		return ikeSetup{}, errors.New(ikeLoginUnsupported(c.Auth))
	}
	if c.Cert == nil || c.Key == nil {
		return ikeSetup{}, errors.New("the profile's certificate or its key is missing")
	}
	path := func(f string) string { return filepath.Join(dir, name+"."+f) }
	st := ikeSetup{Conf: path("conf"), Socket: path("vici")}

	keyDER, err := x509.MarshalPKCS8PrivateKey(c.Key)
	if err != nil {
		return ikeSetup{}, fmt.Errorf("the profile's key: %w", err)
	}
	pemOf := func(typ string, der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}) }
	st.Files = append(st.Files,
		ikeFile{Name: path("key.pem"), Data: pemOf("PRIVATE KEY", keyDER)},
		ikeFile{Name: path("cert.pem"), Data: pemOf("CERTIFICATE", c.Cert.Raw)},
	)
	// charon-cmd trusts every certificate it's given: the profile's CAs
	// and the login certificate's intermediates, or else the system's CAs.
	var trust []*x509.Certificate
	trust = append(trust, c.Chain...)
	trust = append(trust, c.CAs...)
	if len(trust) == 0 {
		if len(roots) == 0 {
			return ikeSetup{}, errors.New("the profile carries no certificate authority to check the server with, " +
				"and this system's trusted ones couldn't be read")
		}
		trust = roots
	}
	for i, ca := range trust {
		st.Files = append(st.Files, ikeFile{Name: path(fmt.Sprintf("ca%d.pem", i)), Data: pemOf("CERTIFICATE", ca.Raw)})
	}
	st.Files = append(st.Files, ikeFile{Name: st.Conf, Data: []byte(ikeConf(runtime.GOOS, st.Socket))})

	local := c.LocalID
	if local == "" {
		local = c.Cert.Subject.CommonName
	}
	st.Args = []string{
		"--debug", "1",
		"--host", host,
		"--identity", local,
		"--remote-identity", c.RemoteID,
		"--profile", "ikev2-pub",
		"--cert", path("cert.pem"),
		"--priv", path("key.pem"),
	}
	for i := range trust {
		st.Args = append(st.Args, "--cert", path(fmt.Sprintf("ca%d.pem", i)))
	}
	if c.IKEProposal != "" {
		st.Args = append(st.Args, "--ike-proposal", c.IKEProposal)
	}
	if c.ESPProposal != "" {
		st.Args = append(st.Args, "--esp-proposal", c.ESPProposal)
	}
	// The whole v4 (and v6) space: the server's full tunnel. Only the
	// networks the engine routes into the interface ever reach it.
	st.Args = append(st.Args, "--remote-ts", "0.0.0.0/0")
	if v6 {
		st.Args = append(st.Args, "--remote-ts", "::/0")
	}
	return st, nil
}

// ikeConf is a session's strongswan.conf: charon-cmd alone reads it
// (STRONGSWAN_CONF), so nothing from a system strongSwan applies. Random
// IKE ports (another IKE client, or a second tunnel, may hold 500/4500);
// the virtual IP on the TUN, where the engine finds it; VICI on the
// session's own socket.
//
// No routes: the engine routes the tunnel's networks, through the Apply
// Protocol, and charon's own for a 0.0.0.0/0 traffic selector would take
// every connection. kernel-libipsec ignores install_routes upstream; the
// charon-cmd RiftRoute ships on macOS is built to honour it
// (packaging/strongswan). On Linux, where charon-cmd is the distribution's,
// its routes go to a table of their own whose rule comes after main's (and
// default's), so main's default route answers every lookup first.
func ikeConf(goos, socket string) string {
	linux := ""
	if goos == "linux" {
		linux = fmt.Sprintf("    routing_table = %d\n    routing_table_prio = %d\n", ikeRoutingTable, ikeRoutingTable)
	}
	return fmt.Sprintf(`# written by riftrouted for one charon-cmd session; not read by anything else
charon-cmd {
    load = %s
    port = 0
    port_nat_t = 0
    install_routes = no
    install_virtual_ip = yes
%s    plugins {
        vici {
            socket = unix://%s
        }
    }
}
`, ikePlugins(goos), linux, socket)
}

// ikeRoutingTable is the Linux table (and rule priority, after main's 32766
// and default's 32767) charon-cmd's unwanted routes go to.
const ikeRoutingTable = 52520

// ikeLoginUnsupported says why a profile's login can't run yet.
func ikeLoginUnsupported(a IKEv2Auth) string {
	switch a {
	case IKEv2EAP:
		return "this profile logs in with a username and password (EAP); RiftRoute runs IKEv2 profiles that log in with a certificate for now"
	case IKEv2PSK:
		return "this profile logs in with a shared secret; RiftRoute runs IKEv2 profiles that log in with a certificate for now"
	}
	return fmt.Sprintf("this profile's login (%s) isn't one RiftRoute runs", a)
}
