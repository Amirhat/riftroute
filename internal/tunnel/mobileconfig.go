package tunnel

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// IKEv2Auth is how an IKEv2 tunnel logs in.
type IKEv2Auth string

const (
	// IKEv2Certificate: a personal certificate and its key (a PKCS#12 in
	// the profile).
	IKEv2Certificate IKEv2Auth = "certificate"
	// IKEv2EAP: a username and password (EAP-MSCHAPv2), the server proving
	// itself with its certificate.
	IKEv2EAP IKEv2Auth = "eap"
	// IKEv2PSK: a shared secret on both sides.
	IKEv2PSK IKEv2Auth = "psk"
)

// IKEv2Config is an IKEv2 VPN as a configuration profile (.mobileconfig)
// describes it: where the server is, who each side says it is, how the
// client logs in and what the server's certificate must chain to, and the
// cryptography both sides agree on. Only what a split tunnel keeps: the
// profile's routes, DNS and on-demand rules are RiftRoute's to decide.
type IKEv2Config struct {
	// Name is the VPN's name in the profile (UserDefinedName).
	Name string
	// Remote is the server (RemoteAddress), UDP 500 then 4500.
	Remote   Remote
	RemoteID string
	LocalID  string

	Auth IKEv2Auth
	// Cert, Key and Chain are the personal certificate, its private key
	// and any intermediates the PKCS#12 carries (IKEv2Certificate).
	Cert  *x509.Certificate
	Key   crypto.PrivateKey
	Chain []*x509.Certificate
	// Username and Password log in with EAP (IKEv2EAP); PSK is the shared
	// secret (IKEv2PSK).
	Username, Password, PSK string

	// CAs are the certificates the profile carries to trust the server
	// with (its root, and any intermediates).
	CAs []*x509.Certificate
	// ServerCertCN and ServerCertIssuerCN, when set, are what the server's
	// certificate must say.
	ServerCertCN, ServerCertIssuerCN string

	// IKEProposal and ESPProposal are charon's proposal strings
	// (aes256gcm16-prfsha256-ecp384, aes256gcm16-ecp384).
	IKEProposal, ESPProposal string
	IKELifetime, ESPLifetime time.Duration
	MOBIKE                   bool
	// DPD is how often dead-peer detection checks the server (0: never).
	DPD time.Duration

	// Ignored lists what the profile asks for that RiftRoute doesn't do
	// (its full tunnel, on-demand rules, the proxy, …).
	Ignored []string
}

// The configuration profile payload types RiftRoute reads.
const (
	payloadVPN    = "com.apple.vpn.managed"
	payloadPKCS12 = "com.apple.security.pkcs12"
	payloadRoot   = "com.apple.security.root"
	payloadPKCS1  = "com.apple.security.pkcs1"
	payloadPEM    = "com.apple.security.pem"
)

// IsMobileconfig reports whether raw is a configuration profile, signed or
// not: a property list whose PayloadType is Configuration.
func IsMobileconfig(raw string) bool {
	b := []byte(raw)
	if inner, ok := unwrapSigned(b); ok {
		b = inner
	}
	v, err := parsePlist(b)
	if err != nil {
		return false
	}
	m, _ := v.(map[string]any)
	return str(m, "PayloadType") == "Configuration"
}

// MobileconfigText returns a profile file's XML: the file itself, or the
// profile a signed one carries (a signed profile is binary, and a tunnel's
// config is text).
func MobileconfigText(data []byte) (string, bool) {
	if inner, ok := unwrapSigned(data); ok {
		data = inner
	}
	if !IsMobileconfig(string(data)) {
		return "", false
	}
	return string(data), true
}

// ParseMobileconfig reads the IKEv2 VPN in a configuration profile (signed
// or not). It refuses a profile without one — an L2TP or Cisco IPSec VPN,
// or none — and a login it can't use (a PKCS#12 it can't open), saying why.
func ParseMobileconfig(raw string) (*IKEv2Config, error) {
	data := []byte(raw)
	if inner, ok := unwrapSigned(data); ok {
		data = inner
	}
	v, err := parsePlist(data)
	if err != nil {
		return nil, &ProfileError{Msg: "this isn't a configuration profile (.mobileconfig): " + err.Error()}
	}
	top, _ := v.(map[string]any)
	if str(top, "PayloadType") != "Configuration" {
		return nil, &ProfileError{Msg: "this isn't a configuration profile (.mobileconfig)"}
	}
	payloads := dicts(top, "PayloadContent")
	byUUID := map[string]map[string]any{}
	var vpns []map[string]any
	for _, p := range payloads {
		if u := str(p, "PayloadUUID"); u != "" {
			byUUID[u] = p
		}
		if str(p, "PayloadType") == payloadVPN {
			vpns = append(vpns, p)
		}
	}
	var vpn map[string]any
	var others []string
	for _, p := range vpns {
		if t := str(p, "VPNType"); t == "IKEv2" {
			if vpn == nil {
				vpn = p
			}
		} else {
			others = append(others, vpnTypeName(p))
		}
	}
	if vpn == nil {
		switch {
		case len(others) > 0:
			return nil, &ProfileError{Msg: fmt.Sprintf("this profile's VPN is %s; RiftRoute runs IKEv2 profiles", strings.Join(others, ", "))}
		default:
			return nil, &ProfileError{Msg: "this profile has no VPN in it"}
		}
	}
	ike := dict(vpn, "IKEv2")
	if ike == nil {
		return nil, &ProfileError{Msg: "the profile's IKEv2 VPN has no IKEv2 settings"}
	}
	c := &IKEv2Config{
		Name:               strings.TrimSpace(str(vpn, "UserDefinedName")),
		RemoteID:           str(ike, "RemoteIdentifier"),
		LocalID:            str(ike, "LocalIdentifier"),
		ServerCertCN:       str(ike, "ServerCertificateCommonName"),
		ServerCertIssuerCN: str(ike, "ServerCertificateIssuerCommonName"),
		MOBIKE:             !boolish(ike, "DisableMOBIKE"),
	}
	host := strings.TrimSpace(str(ike, "RemoteAddress"))
	if host == "" {
		return nil, &ProfileError{Msg: "the IKEv2 VPN has no server (RemoteAddress)"}
	}
	if !validHost(host) {
		return nil, &ProfileError{Msg: fmt.Sprintf("the server %q isn't a host name or address", host)}
	}
	c.Remote = Remote{Host: host, Port: 500, Proto: "udp"}
	if c.RemoteID == "" {
		c.RemoteID = host
	}

	// The CAs the server's certificate must chain to.
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

	extended := boolish(ike, "ExtendedAuthEnabled")
	switch method := str(ike, "AuthenticationMethod"); {
	case extended:
		// EAP: a username and password; the server proves itself with its
		// certificate (method None) — or, with Certificate, both.
		c.Auth = IKEv2EAP
		c.Username, c.Password = str(ike, "AuthName"), str(ike, "AuthPassword")
		if c.Username == "" {
			return nil, &ProfileError{Msg: "the profile logs in with a username and password (EAP) but has no username (AuthName)"}
		}
		if method == "Certificate" {
			c.Ignored = append(c.Ignored, "a certificate beside EAP (the username and password log in)")
		}
	case method == "SharedSecret":
		c.Auth = IKEv2PSK
		c.PSK = str(ike, "SharedSecret")
		if c.PSK == "" {
			return nil, &ProfileError{Msg: "the profile logs in with a shared secret but has none (SharedSecret)"}
		}
	case method == "Certificate", method == "":
		c.Auth = IKEv2Certificate
		uuid := str(ike, "PayloadCertificateUUID")
		p := byUUID[uuid]
		if p == nil {
			// One PKCS#12 in the profile: that's the one.
			var p12s []map[string]any
			for _, q := range payloads {
				if str(q, "PayloadType") == payloadPKCS12 {
					p12s = append(p12s, q)
				}
			}
			if len(p12s) != 1 {
				return nil, &ProfileError{Msg: "the profile logs in with a certificate but doesn't carry it (a PKCS#12 identity)"}
			}
			p = p12s[0]
		}
		if str(p, "PayloadType") != payloadPKCS12 {
			return nil, &ProfileError{Msg: "the profile's login certificate isn't a PKCS#12 identity"}
		}
		key, cert, chain, err := pkcs12.DecodeChain(bytesv(p, "PayloadContent"), str(p, "Password"))
		if err != nil {
			return nil, &ProfileError{Msg: "the profile's certificate can't be opened: " + err.Error()}
		}
		c.Key, c.Cert, c.Chain = key, cert, chain
		if c.LocalID == "" {
			c.LocalID = cert.Subject.CommonName
		}
	default:
		return nil, &ProfileError{Msg: fmt.Sprintf("the profile's login (%s) isn't one RiftRoute runs", method)}
	}
	if c.Auth != IKEv2PSK && len(c.CAs) == 0 {
		// The server's certificate must chain to a public CA.
		c.Ignored = append(c.Ignored, "no CA in the profile (the server's certificate must chain to a public one)")
	}

	if c.IKEProposal, c.IKELifetime, err = proposal(dict(ike, "IKESecurityAssociationParameters"), true, true); err != nil {
		return nil, &ProfileError{Msg: "IKE: " + err.Error()}
	}
	if c.ESPProposal, c.ESPLifetime, err = proposal(dict(ike, "ChildSecurityAssociationParameters"), false, boolish(ike, "EnablePFS")); err != nil {
		return nil, &ProfileError{Msg: "ESP: " + err.Error()}
	}
	switch rate := str(ike, "DeadPeerDetectionRate"); rate {
	case "None":
	case "Low":
		c.DPD = 30 * time.Minute
	case "", "Medium":
		c.DPD = 10 * time.Minute
	case "High":
		c.DPD = time.Minute
	default:
		return nil, &ProfileError{Msg: fmt.Sprintf("unknown DeadPeerDetectionRate %q", rate)}
	}

	// What a split tunnel leaves out: the server's full tunnel always.
	c.Ignored = append(c.Ignored, "the full tunnel (only the networks you list go through it)")
	if boolish(vpn, "OnDemandEnabled") || boolish(ike, "OnDemandEnabled") {
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
	return c, nil
}

// Servers are the profile's server, for display.
func (c *IKEv2Config) Servers() []string { return []string{c.Remote.Host + " (IKEv2)"} }

// CertExpires is when the login certificate stops working (zero without
// one).
func (c *IKEv2Config) CertExpires() time.Time {
	if c.Cert == nil {
		return time.Time{}
	}
	return c.Cert.NotAfter
}

// vpnTypeName names a VPN payload's type for the user.
func vpnTypeName(p map[string]any) string {
	switch t := str(p, "VPNType"); t {
	case "L2TP":
		return "L2TP/IPsec"
	case "IPSec":
		return "Cisco IPsec (IKEv1)"
	case "VPN":
		if s := str(p, "VPNSubType"); s != "" {
			return "an app VPN (" + s + ")"
		}
		return "an app VPN"
	case "":
		return "of no type"
	default:
		return t
	}
}

// Apple's names for the IKE/ESP algorithms, as charon spells them.
var (
	encAlgs = map[string]struct {
		name string
		aead bool
	}{
		"DES": {"des", false}, "3DES": {"3des", false},
		"AES-128": {"aes128", false}, "AES-256": {"aes256", false},
		"AES-128-GCM": {"aes128gcm16", true}, "AES-256-GCM": {"aes256gcm16", true},
		"ChaCha20Poly1305": {"chacha20poly1305", true},
	}
	intAlgs = map[string]string{
		"SHA1-96": "sha1", "SHA1-160": "sha1_160", "SHA2-256": "sha256", "SHA2-384": "sha384", "SHA2-512": "sha512",
	}
	dhGroups = map[int64]string{
		1: "modp768", 2: "modp1024", 5: "modp1536", 14: "modp2048", 15: "modp3072", 16: "modp4096",
		17: "modp6144", 18: "modp8192", 19: "ecp256", 20: "ecp384", 21: "ecp521", 31: "curve25519", 32: "curve448",
	}
)

// proposal turns an SA parameters dict into a charon proposal and its
// lifetime, with Apple's defaults (AES-256, SHA2-256, group 14, 1440 min)
// for what it leaves out. An IKE proposal always has a group; an ESP one
// only with PFS.
func proposal(p map[string]any, ike, pfs bool) (string, time.Duration, error) {
	encName := str(p, "EncryptionAlgorithm")
	if encName == "" {
		encName = "AES-256"
	}
	enc, ok := encAlgs[encName]
	if !ok {
		return "", 0, fmt.Errorf("unknown encryption %q", encName)
	}
	intName := str(p, "IntegrityAlgorithm")
	if intName == "" {
		intName = "SHA2-256"
	}
	integ, ok := intAlgs[intName]
	if !ok {
		return "", 0, fmt.Errorf("unknown integrity %q", intName)
	}
	group := int64(14)
	if g, ok := p["DiffieHellmanGroup"].(int64); ok {
		group = g
	}
	dh, ok := dhGroups[group]
	if !ok {
		return "", 0, fmt.Errorf("unknown Diffie-Hellman group %d", group)
	}
	parts := []string{enc.name}
	switch {
	case enc.aead && ike:
		parts = append(parts, "prf"+strings.TrimSuffix(integ, "_160")) // AEAD: integrity names the PRF
	case !enc.aead:
		parts = append(parts, integ)
	}
	if ike || pfs {
		parts = append(parts, dh)
	}
	life := 1440 * time.Minute
	if m, ok := p["LifeTimeInMinutes"].(int64); ok && m > 0 {
		life = time.Duration(m) * time.Minute
	}
	return strings.Join(parts, "-"), life, nil
}

// parseCerts reads DER or PEM certificates.
func parseCerts(b []byte) ([]*x509.Certificate, error) {
	if len(b) == 0 {
		return nil, errors.New("it's empty")
	}
	if !bytes.Contains(b, []byte("-----BEGIN")) {
		return x509.ParseCertificates(b)
	}
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		cs, err := x509.ParseCertificates(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, cs...)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificate in it")
	}
	return out, nil
}

// validHost reports whether s is an IP address or a DNS name.
func validHost(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// --- plist accessors ---

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func dict(m map[string]any, k string) map[string]any {
	d, _ := m[k].(map[string]any)
	return d
}

func dicts(m map[string]any, k string) []map[string]any {
	a, _ := m[k].([]any)
	var out []map[string]any
	for _, v := range a {
		if d, ok := v.(map[string]any); ok {
			out = append(out, d)
		}
	}
	return out
}

func bytesv(m map[string]any, k string) []byte {
	switch v := m[k].(type) {
	case []byte:
		return v
	case string: // a PEM payload written as text
		return []byte(v)
	}
	return nil
}

// boolish reads a flag the way profiles write them: <true/>, or 1/0.
func boolish(m map[string]any, k string) bool {
	switch v := m[k].(type) {
	case bool:
		return v
	case int64:
		return v != 0
	case string:
		return v == "1" || strings.EqualFold(v, "true")
	}
	return false
}
