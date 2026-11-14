package tunnel

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// L2TPIPsec is what protects an L2TP tunnel.
type L2TPIPsec string

const (
	// L2TPPSK: IPsec with a pre-shared key (the usual).
	L2TPPSK L2TPIPsec = "psk"
	// L2TPCertificate: IPsec with a personal certificate and its key.
	L2TPCertificate L2TPIPsec = "certificate"
	// L2TPNoIPsec: none. Nothing is encrypted; only when the user says so
	// (IPsec = none), and the card says it.
	L2TPNoIPsec L2TPIPsec = "none"
)

// L2TPConfig is an L2TP/IPsec VPN (docs/tunnels-l2tp.md): from a
// configuration profile (.mobileconfig, VPNType L2TP) or RiftRoute's own
// [L2TP] file. The PPP login (username and password) is the tunnel's, as an
// OpenVPN one's is; a profile may carry it.
type L2TPConfig struct {
	// Name is the VPN's name in a profile (UserDefinedName).
	Name   string
	Remote Remote // the server, UDP 1701
	IPsec  L2TPIPsec
	PSK    string
	// Cert, Key and Chain are the personal certificate, its key and any
	// intermediates (L2TPCertificate); CAs, what the server's must chain to.
	Cert  *x509.Certificate
	Key   crypto.PrivateKey
	Chain []*x509.Certificate
	CAs   []*x509.Certificate
	// LocalID and RemoteID are IPsec's identities, when the server wants
	// particular ones.
	LocalID, RemoteID string
	// IKEVersion is 1 (L2TP/IPsec servers' usual, the default) or 2.
	IKEVersion int
	// Username and Password are the login a profile or the file carries.
	Username, Password string
	Ignored            []string
}

// Servers are its server, for display.
func (c *L2TPConfig) Servers() []string {
	what := "L2TP/IPsec"
	if c.IPsec == L2TPNoIPsec {
		what = "L2TP, unencrypted"
	}
	return []string{c.Remote.Host + " (" + what + ")"}
}

// IsL2TP reports whether text is RiftRoute's L2TP file: an [L2TP] section.
func IsL2TP(text string) bool {
	for l := range strings.SplitSeq(text, "\n") {
		if strings.EqualFold(strings.TrimSpace(l), "[l2tp]") {
			return true
		}
	}
	return false
}

// ParseL2TP reads an L2TP tunnel's configuration: a .mobileconfig with an
// L2TP VPN, or RiftRoute's own file —
//
//	[L2TP]
//	Server = vpn.example.com
//	PreSharedKey = …                 # IPsec with a pre-shared key, or
//	Certificate = <base64 PKCS#12>   # with a certificate (+ CertificatePassword),
//	CA = <base64 DER or PEM>         # the server's CA (repeatable)
//	IPsec = none                     # or none at all: nothing is encrypted
//	LocalIdentifier = …              # optional
//	RemoteIdentifier = …             # optional
//	IKEVersion = 1                   # 1 (default) or 2
//	Username = …                     # optional: the login, else asked for
//
// The secrets stay in the file (or the profile), never on a command line.
func ParseL2TP(text string) (*L2TPConfig, error) {
	if IsMobileconfig(text) {
		return parseL2TPMobileconfig(text)
	}
	if !IsL2TP(text) {
		return nil, &ProfileError{Msg: "this isn't an L2TP configuration: it has no [L2TP] section"}
	}
	c := &L2TPConfig{IKEVersion: 1}
	var p12, p12pass string
	var noIPsec bool
	section := ""
	for i, raw := range strings.Split(text, "\n") {
		l := strings.TrimSpace(raw)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") {
			continue
		}
		if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
			section = strings.ToLower(strings.TrimSpace(l[1 : len(l)-1]))
			if section != "l2tp" {
				return nil, &ProfileError{Msg: fmt.Sprintf("line %d: unknown section [%s]", i+1, l[1:len(l)-1])}
			}
			continue
		}
		if section == "" {
			return nil, &ProfileError{Msg: fmt.Sprintf("line %d: a setting before [L2TP]", i+1)}
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			return nil, &ProfileError{Msg: fmt.Sprintf("line %d: not a key = value", i+1)}
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "server":
			c.Remote.Host = v
		case "presharedkey", "sharedsecret":
			c.PSK = v
		case "certificate":
			p12 = v
		case "certificatepassword":
			p12pass = v
		case "ca":
			certs, err := decodeCerts(v)
			if err != nil {
				return nil, &ProfileError{Msg: fmt.Sprintf("line %d: the CA can't be read: %v", i+1, err)}
			}
			c.CAs = append(c.CAs, certs...)
		case "ipsec":
			switch strings.ToLower(v) {
			case "none", "off", "no":
				noIPsec = true
			case "yes", "on":
			default:
				return nil, &ProfileError{Msg: fmt.Sprintf("line %d: IPsec = %q (none, or leave it out)", i+1, v)}
			}
		case "localidentifier":
			c.LocalID = v
		case "remoteidentifier":
			c.RemoteID = v
		case "ikeversion":
			n, err := strconv.Atoi(v)
			if err != nil || (n != 1 && n != 2) {
				return nil, &ProfileError{Msg: fmt.Sprintf("line %d: IKEVersion = %q (1 or 2)", i+1, v)}
			}
			c.IKEVersion = n
		case "username":
			c.Username = v
		case "password":
			c.Password = v
		default:
			return nil, &ProfileError{Msg: fmt.Sprintf("line %d: unknown setting %q", i+1, k)}
		}
	}
	if err := c.setServer(); err != nil {
		return nil, err
	}
	switch {
	case noIPsec && (c.PSK != "" || p12 != ""):
		return nil, &ProfileError{Msg: "IPsec = none, but a pre-shared key or certificate is set: which one?"}
	case noIPsec:
		c.IPsec = L2TPNoIPsec
	case c.PSK != "" && p12 != "":
		return nil, &ProfileError{Msg: "both a pre-shared key and a certificate: IPsec logs in with one"}
	case c.PSK != "":
		c.IPsec = L2TPPSK
	case p12 != "":
		der, err := base64.StdEncoding.DecodeString(p12)
		if err != nil {
			return nil, &ProfileError{Msg: "the certificate isn't base64 (a PKCS#12)"}
		}
		if err := c.setP12(der, p12pass); err != nil {
			return nil, err
		}
	default:
		return nil, &ProfileError{Msg: "no IPsec login: set PreSharedKey or Certificate (or IPsec = none, which encrypts nothing)"}
	}
	return c, c.check()
}

func (c *L2TPConfig) setServer() error {
	if c.Remote.Host == "" {
		return &ProfileError{Msg: "no server (Server = …)"}
	}
	if !validHost(c.Remote.Host) {
		return &ProfileError{Msg: fmt.Sprintf("the server %q isn't a host name or address", c.Remote.Host)}
	}
	c.Remote.Port, c.Remote.Proto = 1701, "udp"
	return nil
}

func (c *L2TPConfig) setP12(der []byte, password string) error {
	key, cert, chain, err := pkcs12.DecodeChain(der, password)
	if err != nil {
		return &ProfileError{Msg: "the certificate can't be opened: " + err.Error()}
	}
	c.IPsec, c.Key, c.Cert, c.Chain = L2TPCertificate, key, cert, chain
	if c.LocalID == "" {
		c.LocalID = cert.Subject.CommonName
	}
	return nil
}

func (c *L2TPConfig) check() error {
	if c.IPsec == L2TPCertificate && len(c.CAs) == 0 {
		c.Ignored = append(c.Ignored, "no CA (the server's certificate must chain to a public one)")
	}
	for _, s := range []string{c.LocalID, c.RemoteID, c.Username} {
		if strings.ContainsAny(s, "\x00\n\r") {
			return &ProfileError{Msg: "an identity or username with a line break"}
		}
	}
	return nil
}

// decodeCerts reads base64 DER, or PEM (inline, or its base64).
func decodeCerts(v string) ([]*x509.Certificate, error) {
	if strings.Contains(v, "-----BEGIN") {
		return parseCerts([]byte(v))
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("not base64")
	}
	return parseCerts(b)
}

// parseL2TPMobileconfig reads the L2TP VPN in a configuration profile:
// PPP's server and login, IPSec's shared secret or certificate.
func parseL2TPMobileconfig(raw string) (*L2TPConfig, error) {
	payloads, vpn, err := profileVPN(raw, "L2TP")
	if err != nil {
		return nil, err
	}
	ppp, ipsec := dict(vpn, "PPP"), dict(vpn, "IPSec")
	if ppp == nil {
		return nil, &ProfileError{Msg: "the profile's L2TP VPN has no PPP settings"}
	}
	c := &L2TPConfig{
		Name:       strings.TrimSpace(str(vpn, "UserDefinedName")),
		IKEVersion: 1,
		Username:   str(ppp, "AuthName"),
		Password:   str(ppp, "AuthPassword"),
	}
	c.Remote.Host = strings.TrimSpace(str(ppp, "CommRemoteAddress"))
	if err := c.setServer(); err != nil {
		return nil, err
	}
	for _, p := range payloads {
		switch str(p, "PayloadType") {
		case payloadRoot, payloadPKCS1, payloadPEM:
			certs, err := parseCerts(bytesv(p, "PayloadContent"))
			if err != nil {
				return nil, &ProfileError{Msg: fmt.Sprintf("the certificate %q in the profile can't be read: %v", str(p, "PayloadDisplayName"), err)}
			}
			c.CAs = append(c.CAs, certs...)
		}
	}
	if ipsec == nil {
		return nil, &ProfileError{Msg: "the profile's L2TP VPN has no IPSec settings; RiftRoute runs L2TP without IPsec only from its own file (IPsec = none)"}
	}
	c.LocalID = str(ipsec, "LocalIdentifier")
	switch method := str(ipsec, "AuthenticationMethod"); method {
	case "SharedSecret", "":
		// Apple's profiles carry it as data; some tools write a string.
		c.PSK = string(bytesv(ipsec, "SharedSecret"))
		if c.PSK == "" {
			c.PSK = str(ipsec, "SharedSecret")
		}
		if c.PSK == "" {
			return nil, &ProfileError{Msg: "the profile's L2TP VPN uses a shared secret but has none (SharedSecret)"}
		}
		c.IPsec = L2TPPSK
	case "Certificate":
		var p map[string]any
		for _, q := range payloads {
			if str(q, "PayloadUUID") == str(ipsec, "PayloadCertificateUUID") && str(q, "PayloadType") == payloadPKCS12 {
				p = q
			}
		}
		if p == nil {
			var p12s []map[string]any
			for _, q := range payloads {
				if str(q, "PayloadType") == payloadPKCS12 {
					p12s = append(p12s, q)
				}
			}
			if len(p12s) != 1 {
				return nil, &ProfileError{Msg: "the profile's L2TP VPN logs in with a certificate but doesn't carry it (a PKCS#12 identity)"}
			}
			p = p12s[0]
		}
		if err := c.setP12(bytesv(p, "PayloadContent"), str(p, "Password")); err != nil {
			return nil, err
		}
	default:
		return nil, &ProfileError{Msg: fmt.Sprintf("the profile's IPsec login (%s) isn't one RiftRoute runs", method)}
	}
	c.Ignored = append(c.Ignored, "the full tunnel (only the networks you list go through it)")
	if boolish(vpn, "OnDemandEnabled") {
		c.Ignored = append(c.Ignored, "connect on demand")
	}
	if _, ok := vpn["DNS"]; ok {
		c.Ignored = append(c.Ignored, "the profile's DNS")
	}
	if _, ok := vpn["Proxies"]; ok {
		c.Ignored = append(c.Ignored, "the proxy")
	}
	slices.Sort(c.Ignored)
	c.Ignored = slices.Compact(c.Ignored)
	return c, c.check()
}

// profileVPN reads a configuration profile's payloads and its first VPN of
// this type, or says what the profile holds instead.
func profileVPN(raw, vpnType string) ([]map[string]any, map[string]any, error) {
	data := []byte(raw)
	if inner, ok := unwrapSigned(data); ok {
		data = inner
	}
	v, err := parsePlist(data)
	if err != nil {
		return nil, nil, &ProfileError{Msg: "this isn't a configuration profile (.mobileconfig): " + err.Error()}
	}
	top, _ := v.(map[string]any)
	if str(top, "PayloadType") != "Configuration" {
		return nil, nil, &ProfileError{Msg: "this isn't a configuration profile (.mobileconfig)"}
	}
	payloads := dicts(top, "PayloadContent")
	var others []string
	for _, p := range payloads {
		if str(p, "PayloadType") != payloadVPN {
			continue
		}
		if str(p, "VPNType") == vpnType {
			return payloads, p, nil
		}
		others = append(others, vpnTypeName(p))
	}
	if len(others) > 0 {
		return nil, nil, &ProfileError{Msg: fmt.Sprintf("this profile's VPN is %s, not %s", strings.Join(others, ", "), vpnTypeName(map[string]any{"VPNType": vpnType}))}
	}
	return nil, nil, &ProfileError{Msg: "this profile has no VPN in it"}
}

// MobileconfigVPNType is the type of a profile's first VPN ("IKEv2",
// "L2TP", …; "" for none): which kind of tunnel it makes.
func MobileconfigVPNType(raw string) string {
	data := []byte(raw)
	if inner, ok := unwrapSigned(data); ok {
		data = inner
	}
	v, err := parsePlist(data)
	if err != nil {
		return ""
	}
	top, _ := v.(map[string]any)
	for _, p := range dicts(top, "PayloadContent") {
		if str(p, "PayloadType") == payloadVPN {
			return str(p, "VPNType")
		}
	}
	return ""
}

// pemCert and pemKey encode for charon.
func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func pemKey(k crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
