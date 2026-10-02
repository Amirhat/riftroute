package tunnel

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
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
	// STRONGSWAN_CONF, and Socket the VICI socket it listens on. Stdin
	// answers the secrets it asks for (a PKCS#12's password, the EAP
	// password, the shared secret).
	Args                []string
	Conf, Socket, Stdin string
}

// ikePlugins are what a session loads: IKEv2 with userspace ESP over a TUN
// (kernel-libipsec) — the interface the tunnel's routes go into — the OS's
// routing (addresses only: charon-cmd installs no routes), VICI (how the
// daemon follows it), keys and certificates (OpenSSL's crypto: GCM, the
// elliptic curves), EAP-MSCHAPv2. No DNS plugin, so the server's DNS is
// never applied; no updown, no attr. A plugin that's missing is left out
// (a distribution's packages may not have them all), and the log says so
// (ikeEssential names the ones a session can't do without). Only the ones
// whose every feature always loads are marked critical (!), which makes
// charon-cmd refuse to start without them: pem's DSA or PGP keys, or
// kernel-netlink's IPsec (kernel-libipsec's instead), would fail it.
func ikePlugins(goos string, p12 bool) string {
	net := "kernel-netlink"
	if goos == "darwin" {
		net = "kernel-pfroute"
	}
	ps := []string{
		"random", "nonce", "openssl", "kdf", "pem", "pkcs1", "pkcs8", "x509", "pubkey", "constraints",
		"md4", "des", "eap-identity", "eap-mschapv2",
		"kernel-libipsec!", net, "socket-default!", "vici!",
	}
	if p12 {
		ps = append(ps, "pkcs7", "pkcs12")
	}
	return strings.Join(ps, " ")
}

// ikeEssential are the plugins no session connects without: a failed
// attempt whose log says one is missing is explained by it.
var ikeEssential = []string{"openssl", "nonce", "x509", "pem", "pkcs8", "pkcs7", "pkcs12", "kernel-libipsec", "kernel-netlink", "kernel-pfroute", "socket-default", "vici"}

// ikeEAPPlugins are the ones a username and password log in with (MD4,
// which MSCHAPv2 needs, is OpenSSL's where strongSwan's md4 isn't there).
var ikeEAPPlugins = []string{"eap-identity", "eap-mschapv2"}

// ikeKeyAsP12 reports whether a charon-cmd of this version takes the login
// key only as a PKCS#12 (--p12): --priv, for any kind of key, came in
// strongSwan 6.0 (--rsa, before it, takes RSA alone). An unknown version is
// taken to be new. (5.9 also asks for a PKCS#12's password even when it's
// empty: renderIKE hands it one on stdin.)
func ikeKeyAsP12(version string) bool {
	m := reMajor.FindStringSubmatch(version)
	if m == nil {
		return false
	}
	major, _ := strconv.Atoi(m[1])
	return major < 6
}

var reMajor = regexp.MustCompile(`^(\d+)\.`)

// ikeLogin is the username and password an EAP login uses: the tunnel's,
// which are the profile's unless the user gave others (the profile may
// leave the password out, for the device to ask).
type ikeLogin struct{ User, Password string }

// ikeSecretMax is the longest password or shared secret charon-cmd reads
// whole: it asks with getpass, which on macOS takes 128 characters.
const ikeSecretMax = 128

// renderIKE lays out one session of the IKEv2 connection c to host (the
// server's address, pinned, or its name) for tunnel name, in dir. login is
// an EAP login's username and password. roots are the CAs to trust the
// server with when the profile carries none (the system's). v6 asks the
// server for IPv6 too (the tunnel routes some). p12 hands charon-cmd the
// login certificate and key as a PKCS#12 (an older charon-cmd:
// ikeKeyAsP12) rather than as PEM files.
//
// Secrets go on charon-cmd's stdin, never in its arguments: it asks for
// them (getpass, which reads stdin when there's no terminal, as the daemon
// runs it), one line each, in the order it needs them.
func renderIKE(c *IKEv2Config, login ikeLogin, roots []*x509.Certificate, host, dir, name string, v6, p12 bool) (ikeSetup, error) {
	path := func(f string) string { return filepath.Join(dir, name+"."+f) }
	st := ikeSetup{Conf: path("conf"), Socket: path("vici")}
	pemOf := func(typ string, der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}) }
	secret := func(what, v string) error {
		switch {
		case v == "":
			return fmt.Errorf("the %s is missing", what)
		case len(v) > ikeSecretMax:
			return fmt.Errorf("the %s is longer than %d characters, which strongSwan can't read", what, ikeSecretMax)
		case strings.ContainsAny(v, "\r\n\x00"):
			return fmt.Errorf("the %s can't contain line breaks", what)
		}
		st.Stdin += v + "\n"
		return nil
	}

	var local, profile string
	var auth []string // the login's arguments
	usesP12 := false
	switch c.Auth {
	case IKEv2Certificate:
		if c.Cert == nil || c.Key == nil {
			return ikeSetup{}, errors.New("the profile's certificate or its key is missing")
		}
		local, profile = orString(c.LocalID, c.Cert.Subject.CommonName), "ikev2-pub"
		if p12 {
			// charon-cmd asks for the password. A fresh random one; the file
			// is as private as the PEM key would be. 3DES and SHA-1: what
			// every strongSwan reads.
			var pw [16]byte
			if _, err := rand.Read(pw[:]); err != nil {
				return ikeSetup{}, err
			}
			b, err := pkcs12.LegacyDES.Encode(c.Key, c.Cert, nil, hex.EncodeToString(pw[:]))
			if err != nil {
				return ikeSetup{}, fmt.Errorf("the profile's key: %w", err)
			}
			_ = secret("PKCS#12 password", hex.EncodeToString(pw[:]))
			st.Files = append(st.Files, ikeFile{Name: path("p12"), Data: b})
			auth, usesP12 = []string{"--p12", path("p12")}, true
		} else {
			keyDER, err := x509.MarshalPKCS8PrivateKey(c.Key)
			if err != nil {
				return ikeSetup{}, fmt.Errorf("the profile's key: %w", err)
			}
			st.Files = append(st.Files,
				ikeFile{Name: path("key.pem"), Data: pemOf("PRIVATE KEY", keyDER)},
				ikeFile{Name: path("cert.pem"), Data: pemOf("CERTIFICATE", c.Cert.Raw)},
			)
			auth = []string{"--cert", path("cert.pem"), "--priv", path("key.pem")}
		}
	case IKEv2EAP:
		// EAP-MSCHAPv2 with the username and password; the server proves
		// itself with its certificate.
		if login.User == "" {
			return ikeSetup{}, errors.New("the username is missing")
		}
		if err := secret("password", login.Password); err != nil {
			return ikeSetup{}, err
		}
		local, profile = orString(c.LocalID, login.User), "ikev2-eap"
		auth = []string{"--eap-identity", login.User}
	case IKEv2PSK:
		// The shared secret on both sides (strongSwan 6.1 and later).
		if c.LocalID == "" {
			return ikeSetup{}, errors.New("the profile has no LocalIdentifier, which a shared-secret login needs")
		}
		if err := secret("shared secret", c.PSK); err != nil {
			return ikeSetup{}, err
		}
		local, profile = c.LocalID, "ikev2-psk"
	default:
		return ikeSetup{}, errors.New(ikeLoginUnsupported(c.Auth))
	}

	// charon-cmd trusts every certificate it's given: the profile's CAs
	// and the login certificate's intermediates, or else the system's CAs.
	// A shared secret proves the server too: no certificates.
	var trust []*x509.Certificate
	if c.Auth != IKEv2PSK {
		trust = append(trust, c.Chain...)
		trust = append(trust, c.CAs...)
		if len(trust) == 0 {
			if len(roots) == 0 {
				return ikeSetup{}, errors.New("the profile carries no certificate authority to check the server with, " +
					"and this system's trusted ones couldn't be read")
			}
			trust = roots
		}
	}
	for i, ca := range trust {
		st.Files = append(st.Files, ikeFile{Name: path(fmt.Sprintf("ca%d.pem", i)), Data: pemOf("CERTIFICATE", ca.Raw)})
	}
	st.Files = append(st.Files, ikeFile{Name: st.Conf, Data: []byte(ikeConf(runtime.GOOS, st.Socket, usesP12))})

	st.Args = []string{
		"--debug", "1",
		"--host", host,
		"--identity", local,
		"--remote-identity", c.RemoteID,
		"--profile", profile,
	}
	st.Args = append(st.Args, auth...)
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

func orString(s, or string) string {
	if s != "" {
		return s
	}
	return or
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
// its routes (a default route into the tunnel) go to a table of their own
// whose rule never matches: it's for packets carrying a mark nothing sets
// (ikeRuleMark). Its priority, after main's and default's, is a second
// line: a rule after main alone still catches every lookup main can't
// answer — a host's IPv6 on a v4-only network, say.
func ikeConf(goos, socket string, p12 bool) string {
	linux, linuxPlugins := "", ""
	if goos == "linux" {
		linux = fmt.Sprintf("    routing_table = %d\n    routing_table_prio = %d\n", ikeRoutingTable, ikeRoutingTable)
		linuxPlugins = fmt.Sprintf("        kernel-netlink {\n            fwmark = %s\n        }\n", ikeRuleMark)
	}
	return fmt.Sprintf(`# written by riftrouted for one charon-cmd session; not read by anything else
charon-cmd {
    load = %s
    port = 0
    port_nat_t = 0
    install_routes = no
    install_virtual_ip = yes
    # Send our certificate whether or not the server asks for it, as Apple's
    # client does: some servers never ask, and wait for it (RiftRoute's
    # charon-cmd, which does so by default; others ignore the setting).
    send_cert_always = yes
%s    # The tunnel's log (the daemon reads stderr), instead of the default
    # loggers, which add syslog. The library's messages one level deeper:
    # that's where a plugin the system doesn't have is named.
    filelog {
        stderr {
            default = 1
            lib = 2
        }
    }
    plugins {
        vici {
            socket = unix://%s
        }
%s    }
}
`, ikePlugins(goos, p12), linux, socket, linuxPlugins)
}

// ikeRuleMark is the firewall mark (value/mask) charon's routing rule on
// Linux matches: one nothing sets — not RiftRoute's per-app 0x5252, not
// wg-quick's 0xca6c, Tailscale's or Mullvad's — so the rule matches no
// packet.
const ikeRuleMark = "0x7f52ea21/0xffffffff"

// ikeRoutingTable is the Linux table (and rule priority, after main's 32766
// and default's 32767) charon-cmd's unwanted routes go to.
const ikeRoutingTable = 52520

// ikePSKSince is the strongSwan release whose charon-cmd first logs in
// with a shared secret (its ikev2-psk profile).
const ikePSKSince = "6.1"

// ikePSKSupported reports whether a charon-cmd of this version logs in with
// a shared secret. An unknown version is taken to be new.
func ikePSKSupported(version string) bool {
	m := reMinor.FindStringSubmatch(version)
	if m == nil {
		return true
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return major > 6 || major == 6 && minor >= 1
}

var reMinor = regexp.MustCompile(`^(\d+)\.(\d+)`)

// ikeLoginName names a login for the user.
func ikeLoginName(a IKEv2Auth) string {
	switch a {
	case IKEv2Certificate:
		return "a certificate"
	case IKEv2EAP:
		return "a username and password"
	case IKEv2PSK:
		return "a shared secret"
	}
	return string(a)
}

// ikeLoginUnsupported says why a profile's login can't run.
func ikeLoginUnsupported(a IKEv2Auth) string {
	return fmt.Sprintf("this profile's login (%s) isn't one RiftRoute runs", a)
}
