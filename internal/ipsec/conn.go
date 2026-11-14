// Package ipsec runs strongSwan's charon for L2TP/IPsec tunnels: one
// instance, shared by all of them, driven over VICI. Each tunnel's
// connection is an IPsec SA in transport mode covering only UDP between
// this machine and its server on the L2TP port (docs/tunnels-l2tp.md).
package ipsec

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/strongswan/govici/vici"
)

// Conn is one tunnel's IPsec connection.
type Conn struct {
	// Name is unique among the connections loaded (the tunnel's).
	Name   string
	Server netip.Addr
	// Version is IKE's: 1 (L2TP/IPsec servers' usual, the default) or 2.
	Version int
	// PSK is the pre-shared key; else Cert and Key (PEM) log in, the server
	// proven by CAs (PEM).
	PSK       string
	Cert, Key []byte
	// Chain are intermediates between Cert and its CA (PEM), loaded so the
	// server can be sent the whole path.
	Chain [][]byte
	CAs   [][]byte
	// LocalID and RemoteID are the identities, when the server wants
	// particular ones (default: the addresses, as Main Mode with a PSK
	// uses).
	LocalID, RemoteID string
	// Port is the L2TP port, both ends (default 1701).
	Port uint16
}

// Proposals for IKE and ESP: what L2TP/IPsec servers speak, strongest first,
// down to what old ones (Windows' RRAS, MikroTik's defaults, Apple's client)
// still use. strongSwan's defaults follow.
var (
	ikeProposals = []string{
		"aes256-sha256-modp2048", "aes128-sha256-modp2048",
		"aes256-sha1-modp2048", "aes128-sha1-modp2048",
		"aes256-sha1-modp1024", "aes128-sha1-modp1024", "3des-sha1-modp1024",
		"default",
	}
	espProposals = []string{
		"aes256gcm16", "aes128gcm16",
		"aes256-sha256", "aes128-sha256",
		"aes256-sha1", "aes128-sha1", "3des-sha1",
		"default",
	}
)

// child is the name of every connection's CHILD_SA.
const child = "l2tp"

var reName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func (c Conn) check() error {
	switch {
	case !reName.MatchString(c.Name):
		return fmt.Errorf("ipsec: connection name %q", c.Name)
	case !c.Server.IsValid():
		return errors.New("ipsec: no server address")
	case c.PSK == "" && (len(c.Cert) == 0 || len(c.Key) == 0):
		return errors.New("ipsec: neither a pre-shared key nor a certificate and its key")
	case c.Version != 0 && c.Version != 1 && c.Version != 2:
		return fmt.Errorf("ipsec: IKE version %d", c.Version)
	}
	return nil
}

func (c Conn) port() uint16 {
	if c.Port == 0 {
		return 1701
	}
	return c.Port
}

func (c Conn) version() int {
	if c.Version == 0 {
		return 1
	}
	return c.Version
}

// ids are the names its secrets are loaded under (unload-shared/-key).
func (c Conn) pskID() string { return "rr-psk-" + c.Name }

// connMessage is the load-conn message.
func connMessage(c Conn) (*vici.Message, error) {
	ts := fmt.Sprintf("dynamic[17/%d]", c.port()) // UDP; by number: no /etc/protocols needed
	ch := vici.NewMessage()
	for k, v := range map[string]any{
		"mode":          "transport",
		"local_ts":      []string{ts},
		"remote_ts":     []string{ts},
		"esp_proposals": espProposals,
		// The policies stay while the connection is loaded: a packet for the
		// server's L2TP port without an SA starts one, and never leaves in the
		// clear (the SA dropped, being renegotiated).
		"start_action": "trap",
		"dpd_action":   "trap",
		"close_action": "trap",
		"rekey_time":   "1h",
	} {
		if err := ch.Set(k, v); err != nil {
			return nil, err
		}
	}
	children := vici.NewMessage()
	if err := children.Set(child, ch); err != nil {
		return nil, err
	}

	local, remote := vici.NewMessage(), vici.NewMessage()
	if c.PSK != "" {
		_ = local.Set("auth", "psk")
		_ = remote.Set("auth", "psk")
	} else {
		_ = local.Set("auth", "pubkey")
		_ = local.Set("certs", []string{string(c.Cert)})
		_ = remote.Set("auth", "pubkey")
		if len(c.CAs) > 0 {
			var cas []string
			for _, ca := range c.CAs {
				cas = append(cas, string(ca))
			}
			_ = remote.Set("cacerts", cas)
		}
	}
	if c.LocalID != "" {
		_ = local.Set("id", c.LocalID)
	}
	remoteID := c.RemoteID
	if remoteID == "" && c.PSK != "" {
		remoteID = c.Server.String() // Main Mode with a PSK: the address
	}
	if remoteID != "" {
		_ = remote.Set("id", remoteID)
	} else {
		_ = remote.Set("id", "%any")
	}

	conn := vici.NewMessage()
	for k, v := range map[string]any{
		"version":      fmt.Sprint(c.version()),
		"remote_addrs": []string{c.Server.String()},
		"proposals":    ikeProposals,
		"encap":        "yes", // ESP in UDP always: it crosses NATs that drop ESP
		"dpd_delay":    "30s",
		"mobike":       "no",
		"local-1":      local,
		"remote-1":     remote,
		"children":     children,
	} {
		if err := conn.Set(k, v); err != nil {
			return nil, err
		}
	}
	m := vici.NewMessage()
	if err := m.Set(c.Name, conn); err != nil {
		return nil, err
	}
	return m, nil
}

// pskMessage is the load-shared message: the key, for the server's identity.
func pskMessage(c Conn) *vici.Message {
	m := vici.NewMessage()
	owner := c.RemoteID
	if owner == "" {
		owner = c.Server.String()
	}
	_ = m.Set("id", c.pskID())
	_ = m.Set("type", "IKE")
	_ = m.Set("data", c.PSK)
	_ = m.Set("owners", []string{owner})
	return m
}

// keyMessage is the load-key message for a certificate's key.
func keyMessage(c Conn) (*vici.Message, error) {
	typ := keyType(c.Key)
	if typ == "" {
		return nil, errors.New("couldn't read the profile's private key: not a PEM private key")
	}
	m := vici.NewMessage()
	_ = m.Set("type", typ)
	_ = m.Set("data", string(c.Key))
	return m, nil
}

// keyType is load-key's type for a PEM key.
func keyType(pem []byte) string {
	s := string(pem)
	switch {
	case strings.Contains(s, "BEGIN RSA PRIVATE KEY"):
		return "rsa"
	case strings.Contains(s, "BEGIN EC PRIVATE KEY"):
		return "ecdsa"
	case strings.Contains(s, "BEGIN PRIVATE KEY"):
		return "any"
	}
	return ""
}
