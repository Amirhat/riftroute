package tunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/Amirhat/riftroute/internal/domain"
)

// testPKI is a CA and a client certificate it issued, as a profile carries
// them.
type testPKI struct {
	caDER   []byte
	client  *x509.Certificate
	key     *ecdsa.PrivateKey
	caCert  *x509.Certificate
	expires time.Time
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	expires := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "alice@example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: expires,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := x509.ParseCertificate(der)
	return testPKI{caDER: caDER, client: client, key: key, caCert: caCert, expires: expires}
}

func (p testPKI) p12(t *testing.T, enc *pkcs12.Encoder, password string) []byte {
	t.Helper()
	b, err := enc.Encode(p.key, p.client, nil, password)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// profile builds a .mobileconfig: an IKEv2 VPN with ikev2 (raw plist
// fragments, keys and values) and the extra payloads.
func profile(vpnType, ikev2 string, payloads ...string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadDescription</key><string>IKEv2 to vpn.example.com &amp; friends</string>
  <key>PayloadContent</key>
  <array>
    ` + strings.Join(payloads, "\n") + `
    <dict>
      <key>PayloadType</key><string>com.apple.vpn.managed</string>
      <key>PayloadUUID</key><string>VPN-UUID</string>
      <key>UserDefinedName</key><string>Office</string>
      <key>VPNType</key><string>` + vpnType + `</string>
      <key>IKEv2</key>
      <dict>` + ikev2 + `</dict>
    </dict>
  </array>
</dict>
</plist>`
}

func dataPayload(typ, uuid string, content []byte, extra string) string {
	return `<dict>
      <key>PayloadType</key><string>` + typ + `</string>
      <key>PayloadUUID</key><string>` + uuid + `</string>
      <key>PayloadDisplayName</key><string>` + typ + `</string>
      <key>PayloadContent</key><data>
` + base64.StdEncoding.EncodeToString(content) + `
      </data>` + extra + `
    </dict>`
}

const certIKEv2 = `
        <key>RemoteAddress</key><string>vpn.example.com</string>
        <key>RemoteIdentifier</key><string>vpn.example.com</string>
        <key>LocalIdentifier</key><string>alice@example.com</string>
        <key>AuthenticationMethod</key><string>Certificate</string>
        <key>PayloadCertificateUUID</key><string>P12-UUID</string>
        <key>ServerCertificateCommonName</key><string>vpn.example.com</string>
        <key>ExtendedAuthEnabled</key><integer>0</integer>
        <key>EnablePFS</key><integer>1</integer>
        <key>DisableMOBIKE</key><integer>0</integer>
        <key>DeadPeerDetectionRate</key><string>Medium</string>
        <key>IKESecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key><string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key><string>SHA2-256</string>
          <key>DiffieHellmanGroup</key><integer>20</integer>
          <key>LifeTimeInMinutes</key><integer>480</integer>
        </dict>
        <key>ChildSecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key><string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key><string>SHA2-256</string>
          <key>DiffieHellmanGroup</key><integer>20</integer>
          <key>LifeTimeInMinutes</key><integer>60</integer>
        </dict>`

// A certificate profile like the user's: an IKEv2 VPN logging in with a
// personal PKCS#12 — in Apple's legacy encryption and in the modern one —
// trusting the profile's root, with its proposals and timers as charon
// spells them, and the full tunnel noted as left out.
func TestParseCertificateProfile(t *testing.T) {
	pki := newTestPKI(t)
	for name, enc := range map[string]*pkcs12.Encoder{"legacy": pkcs12.LegacyRC2, "modern": pkcs12.Modern2023} {
		t.Run(name, func(t *testing.T) {
			raw := profile("IKEv2", certIKEv2,
				dataPayload(payloadPKCS12, "P12-UUID", pki.p12(t, enc, "s3cret&pw"), `<key>Password</key><string>s3cret&amp;pw</string>`),
				dataPayload(payloadRoot, "CA-UUID", pki.caDER, ""),
			)
			if !IsMobileconfig(raw) {
				t.Fatal("not recognized as a profile")
			}
			c, err := ParseMobileconfig(raw)
			if err != nil {
				t.Fatal(err)
			}
			if c.Name != "Office" || c.Remote != (Remote{Host: "vpn.example.com", Port: 500, Proto: "udp"}) ||
				c.RemoteID != "vpn.example.com" || c.LocalID != "alice@example.com" || c.ServerCertCN != "vpn.example.com" {
				t.Errorf("identity = %+v", c)
			}
			if c.Auth != IKEv2Certificate || c.Cert.Subject.CommonName != "alice@example.com" || c.Key == nil {
				t.Errorf("login = %v %v", c.Auth, c.Cert)
			}
			if !c.CertExpires().Equal(pki.expires) {
				t.Errorf("expires %v, want %v", c.CertExpires(), pki.expires)
			}
			if len(c.CAs) != 1 || !c.CAs[0].Equal(pki.caCert) {
				t.Errorf("CAs = %v", c.CAs)
			}
			if c.IKEProposal != "aes256gcm16-prfsha256-ecp384" || c.ESPProposal != "aes256gcm16-ecp384" {
				t.Errorf("proposals = %q, %q", c.IKEProposal, c.ESPProposal)
			}
			if c.IKELifetime != 8*time.Hour || c.ESPLifetime != time.Hour || !c.MOBIKE || c.DPD != 10*time.Minute {
				t.Errorf("timers = %v %v mobike %v dpd %v", c.IKELifetime, c.ESPLifetime, c.MOBIKE, c.DPD)
			}
			if !strings.Contains(strings.Join(c.Ignored, "; "), "full tunnel") {
				t.Errorf("ignored = %v", c.Ignored)
			}
		})
	}
}

// A wrong PKCS#12 password, a profile whose VPN isn't IKEv2, and one with
// no VPN are each refused with why.
func TestParseRefusesWhatItCantUse(t *testing.T) {
	pki := newTestPKI(t)
	p12 := pki.p12(t, pkcs12.LegacyRC2, "right")
	for name, c := range map[string]struct {
		raw  string
		want string
	}{
		"wrong password": {profile("IKEv2", certIKEv2, dataPayload(payloadPKCS12, "P12-UUID", p12, `<key>Password</key><string>wrong</string>`)), "can't be opened"},
		"L2TP":           {profile("L2TP", ""), "L2TP/IPsec; RiftRoute runs IKEv2"},
		"no VPN":         {strings.Replace(profile("IKEv2", certIKEv2), "com.apple.vpn.managed", "com.apple.wifi.managed", 1), "no VPN"},
		"no server":      {profile("IKEv2", `<key>AuthenticationMethod</key><string>SharedSecret</string><key>SharedSecret</key><string>x</string>`), "no server"},
		"not a profile":  {"[Interface]\nPrivateKey = x\n", "isn't a configuration profile"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseMobileconfig(c.raw); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want %q", err, c.want)
			}
		})
	}
}

// EAP (username and password) and shared-secret profiles, and Apple's
// defaults for the proposals a profile leaves out.
func TestParseEAPAndPSKProfiles(t *testing.T) {
	eap, err := ParseMobileconfig(profile("IKEv2", `
        <key>RemoteAddress</key><string>203.0.113.9</string>
        <key>AuthenticationMethod</key><string>None</string>
        <key>ExtendedAuthEnabled</key><true/>
        <key>AuthName</key><string>alice</string>
        <key>AuthPassword</key><string>pw</string>
        <key>DeadPeerDetectionRate</key><string>High</string>`))
	if err != nil {
		t.Fatal(err)
	}
	if eap.Auth != IKEv2EAP || eap.Username != "alice" || eap.Password != "pw" || eap.RemoteID != "203.0.113.9" || eap.DPD != time.Minute {
		t.Errorf("eap = %+v", eap)
	}
	if eap.IKEProposal != "aes256-sha256-modp2048" || eap.ESPProposal != "aes256-sha256" || eap.IKELifetime != 24*time.Hour {
		t.Errorf("defaults = %q %q %v", eap.IKEProposal, eap.ESPProposal, eap.IKELifetime)
	}

	psk, err := ParseMobileconfig(profile("IKEv2", `
        <key>RemoteAddress</key><string>vpn.example.com</string>
        <key>AuthenticationMethod</key><string>SharedSecret</string>
        <key>SharedSecret</key><string>shh</string>
        <key>DeadPeerDetectionRate</key><string>None</string>`))
	if err != nil {
		t.Fatal(err)
	}
	if psk.Auth != IKEv2PSK || psk.PSK != "shh" || psk.DPD != 0 {
		t.Errorf("psk = %+v", psk)
	}
}

// A signed profile (CMS SignedData around the XML) reads like the XML, and
// MobileconfigText hands back the XML to store.
func TestSignedProfile(t *testing.T) {
	xmlText := profile("IKEv2", `<key>RemoteAddress</key><string>vpn.example.com</string>
        <key>AuthenticationMethod</key><string>SharedSecret</string><key>SharedSecret</key><string>shh</string>`)
	signed := signedData(t, []byte(xmlText))
	if !IsMobileconfig(string(signed)) {
		t.Fatal("a signed profile isn't recognized")
	}
	if c, err := ParseMobileconfig(string(signed)); err != nil || c.PSK != "shh" {
		t.Fatalf("parse = %+v, %v", c, err)
	}
	if got, ok := MobileconfigText(signed); !ok || got != xmlText {
		t.Fatal("MobileconfigText didn't unwrap the XML")
	}
	if _, ok := MobileconfigText([]byte("client\nremote x\n")); ok {
		t.Fatal("an .ovpn taken for a profile")
	}
	// A BER-encoded one (indefinite lengths) with the XML in one piece.
	ber := append([]byte{0x30, 0x80, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, 0xa0, 0x80}, []byte(xmlText)...)
	ber = append(ber, 0, 0, 0, 0)
	if got, ok := MobileconfigText(ber); !ok || got != xmlText {
		t.Fatal("a BER-signed profile wasn't unwrapped")
	}
}

// signedData wraps content as a CMS SignedData with the fields a real
// signature has after it (empty certificates and signer infos).
func signedData(t *testing.T, content []byte) []byte {
	t.Helper()
	encap, err := asn1.Marshal(struct {
		Type    asn1.ObjectIdentifier
		Content []byte `asn1:"explicit,tag:0"`
	}{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}, content})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := asn1.Marshal(struct {
		Version     int
		Digests     asn1.RawValue
		Encap       asn1.RawValue
		Certs       asn1.RawValue
		SignerInfos asn1.RawValue
	}{
		1,
		asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true},
		asn1.RawValue{FullBytes: encap},
		asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true},
		asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	ci, err := asn1.Marshal(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, asn1.RawValue{FullBytes: sd}})
	if err != nil {
		t.Fatal(err)
	}
	return ci
}

// The property list reader takes the value kinds a profile uses and
// refuses malformed ones rather than guessing.
func TestParsePlist(t *testing.T) {
	v, err := parsePlist([]byte(`<plist><dict>
  <key>s</key><string>a &lt;b&gt;</string><key>i</key><integer>-7</integer><key>r</key><real>1.5</real>
  <key>t</key><true/><key>f</key><false/><key>d</key><data>aGk=</data>
  <key>a</key><array><string>x</string><dict/></array><key>when</key><date>2026-09-30T10:00:00Z</date>
</dict></plist>`))
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	got := fmt.Sprintf("%v|%v|%v|%v|%v|%s|%d|%d", m["s"], m["i"], m["r"], m["t"], m["f"], m["d"], len(m["a"].([]any)), m["when"].(time.Time).Year())
	if got != "a <b>|-7|1.5|true|false|hi|2|2026" {
		t.Errorf("values = %s", got)
	}
	for _, bad := range []string{
		`<plist><dict><key>k</key></dict></plist>`,
		`<plist><dict><string>no key</string></dict></plist>`,
		`<plist><integer>x</integer></plist>`,
		`<plist><data>!!!</data></plist>`,
		`<plist><unknown/></plist>`,
		`<notplist/>`,
		strings.Repeat("<plist><array>", 1) + strings.Repeat("<array>", 40) + strings.Repeat("</array>", 41) + "</plist>",
	} {
		if _, err := parsePlist([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// An IKEv2 tunnel saves from its profile: its server, the certificate's
// expiry and what's ignored show in its status; a login beside the profile
// is refused; and it can't connect until strongSwan is part of RiftRoute,
// saying so.
func TestIKEv2TunnelSaves(t *testing.T) {
	h := newHarness(t)
	h.m.o.IKE = &FakeIKE{Missing: true}
	ctx := t.Context()
	pki := newTestPKI(t)
	raw := profile("IKEv2", certIKEv2,
		dataPayload(payloadPKCS12, "P12-UUID", pki.p12(t, pkcs12.LegacyRC2, "pw"), `<key>Password</key><string>pw</string>`),
		dataPayload(payloadRoot, "CA-UUID", pki.caDER, ""))
	spec := domain.TunnelSpec{Name: "office", Type: domain.TunnelIKEv2, Config: raw, Routes: []string{"10.30.0.0/16"}}
	st, err := h.m.Save(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if st.Type != domain.TunnelIKEv2 || strings.Join(st.Servers, ",") != "vpn.example.com (IKEv2)" ||
		st.CertExpires == nil || !st.CertExpires.Equal(pki.expires) || len(st.Ignored) == 0 {
		t.Fatalf("status = %+v", st)
	}
	var ee *EngineError
	if err := h.m.Connect("office"); !errors.As(err, &ee) || !strings.Contains(ee.Error(), "strongSwan") {
		t.Fatalf("connect = %v", err)
	}

	spec.Username = "alice"
	if _, err := h.m.Save(ctx, spec); err == nil || !strings.Contains(err.Error(), "logs in with what its profile carries") {
		t.Fatalf("a username beside the profile: %v", err)
	}
	spec.Username, spec.Config = "", ""
	spec.Name = "empty"
	if _, err := h.m.Save(ctx, spec); err == nil || !strings.Contains(err.Error(), ".mobileconfig") {
		t.Fatalf("no profile: %v", err)
	}
}
