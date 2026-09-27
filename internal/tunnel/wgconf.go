package tunnel

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// WGConfig is a WireGuard tunnel's configuration: the standard wg-quick file
// providers hand out, checked and reduced to what a split tunnel uses. Its
// routes are never taken from it — AllowedIPs only decide which peer a packet
// belongs to — and nothing in it runs: DNS, Table and the Pre/Post hooks are
// ignored (and reported).
type WGConfig struct {
	PrivateKey [32]byte
	Addresses  []netip.Prefix
	MTU        int // 0: the default
	Peers      []WGPeer
	// Ignored lists what was dropped because RiftRoute owns its job,
	// deduplicated and sorted.
	Ignored []string
}

// WGPeer is one [Peer] section.
type WGPeer struct {
	PublicKey    [32]byte
	PresharedKey *[32]byte
	Endpoint     Remote // Proto is always udp
	AllowedIPs   []netip.Prefix
	Keepalive    int // seconds; 0: off
}

// Limits on what a WireGuard config may hold.
const (
	maxWGConfigBytes = 64 << 10
	maxWGPeers       = 16
	maxWGAddresses   = 16
	maxWGAllowedIPs  = 1024
)

// wgIgnored are keys a client needs no part of: RiftRoute owns routes and DNS
// and runs no scripts.
var wgIgnored = map[string]bool{
	"dns": true, "table": true, "preup": true, "postup": true, "predown": true, "postdown": true,
	"saveconfig": true, "listenport": true, "fwmark": true,
}

// ParseWG parses and checks a wg-quick configuration.
func ParseWG(text string) (*WGConfig, error) {
	if len(text) > maxWGConfigBytes {
		return nil, &ProfileError{Msg: fmt.Sprintf("the configuration is larger than %d KiB", maxWGConfigBytes>>10)}
	}
	c := &WGConfig{}
	ignored := map[string]bool{}
	section := ""
	var peer *WGPeer
	sawInterface, sawKey := false, false
	for i, raw := range strings.Split(text, "\n") {
		n := i + 1
		line := strings.TrimSuffix(raw, "\r")
		if strings.IndexFunc(line, func(r rune) bool { return (r < 0x20 && r != '\t') || r == 0x7f }) >= 0 {
			return nil, &ProfileError{Line: n, Msg: "control character"}
		}
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = line[:j]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch strings.ToLower(line) {
			case "[interface]":
				if sawInterface {
					return nil, &ProfileError{Line: n, Msg: "a second [Interface] section"}
				}
				sawInterface, section, peer = true, "interface", nil
			case "[peer]":
				if len(c.Peers) == maxWGPeers {
					return nil, &ProfileError{Line: n, Msg: fmt.Sprintf("more than %d peers", maxWGPeers)}
				}
				c.Peers = append(c.Peers, WGPeer{})
				section, peer = "peer", &c.Peers[len(c.Peers)-1]
			default:
				return nil, &ProfileError{Line: n, Msg: fmt.Sprintf("unknown section %s", line)}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, &ProfileError{Line: n, Msg: "expected key = value"}
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		if section == "" {
			return nil, &ProfileError{Line: n, Msg: key + " outside a section"}
		}
		if section == "interface" && wgIgnored[key] {
			ignored[strings.TrimSpace(strings.SplitN(line, "=", 2)[0])] = true
			continue
		}
		var err error
		switch section + "." + key {
		case "interface.privatekey":
			c.PrivateKey, err = wgKey(value)
			if err == nil && c.PrivateKey == [32]byte{} {
				err = errors.New("the PrivateKey is all zeros")
			}
			sawKey = err == nil
		case "interface.address":
			for _, v := range splitList(value) {
				p, perr := hostPrefix(v)
				if perr != nil {
					err = perr
					break
				}
				c.Addresses = append(c.Addresses, p)
			}
			if len(c.Addresses) > maxWGAddresses {
				err = fmt.Errorf("more than %d addresses", maxWGAddresses)
			}
		case "interface.mtu":
			c.MTU, err = strconv.Atoi(value)
			if err == nil && (c.MTU < 1280 || c.MTU > 9000) {
				err = fmt.Errorf("MTU %d is outside 1280–9000", c.MTU)
			}
		case "peer.publickey":
			peer.PublicKey, err = wgKey(value)
		case "peer.presharedkey":
			var k [32]byte
			if k, err = wgKey(value); err == nil {
				peer.PresharedKey = &k
			}
		case "peer.endpoint":
			peer.Endpoint, err = wgEndpoint(value)
		case "peer.allowedips":
			for _, v := range splitList(value) {
				p, perr := hostPrefix(v)
				if perr != nil {
					err = perr
					break
				}
				peer.AllowedIPs = append(peer.AllowedIPs, p)
			}
			if len(peer.AllowedIPs) > maxWGAllowedIPs {
				err = fmt.Errorf("more than %d allowed IPs", maxWGAllowedIPs)
			}
		case "peer.persistentkeepalive":
			if strings.EqualFold(value, "off") {
				peer.Keepalive = 0
				break
			}
			peer.Keepalive, err = strconv.Atoi(value)
			if err == nil && (peer.Keepalive < 0 || peer.Keepalive > 65535) {
				err = fmt.Errorf("keepalive %d is out of range", peer.Keepalive)
			}
		default:
			return nil, &ProfileError{Line: n, Msg: fmt.Sprintf("%s isn't a WireGuard setting RiftRoute knows", strings.TrimSpace(strings.SplitN(line, "=", 2)[0]))}
		}
		if err != nil {
			return nil, &ProfileError{Line: n, Msg: err.Error()}
		}
	}
	switch {
	case !sawInterface:
		return nil, &ProfileError{Msg: "no [Interface] section"}
	case !sawKey:
		return nil, &ProfileError{Msg: "the [Interface] has no PrivateKey"}
	case len(c.Addresses) == 0:
		return nil, &ProfileError{Msg: "the [Interface] has no Address"}
	case len(c.Peers) == 0:
		return nil, &ProfileError{Msg: "no [Peer]"}
	}
	for i, p := range c.Peers {
		switch {
		case p.PublicKey == [32]byte{}:
			return nil, &ProfileError{Msg: fmt.Sprintf("peer %d has no PublicKey", i+1)}
		case p.Endpoint.Host == "":
			return nil, &ProfileError{Msg: fmt.Sprintf("peer %d has no Endpoint (a client needs one to connect to)", i+1)}
		}
	}
	for k := range ignored {
		c.Ignored = append(c.Ignored, k)
	}
	slices.Sort(c.Ignored)
	return c, nil
}

// Servers are the peers' endpoints, for display ("host:port/udp").
func (c *WGConfig) Servers() []string {
	var out []string
	for _, p := range c.Peers {
		out = append(out, p.Endpoint.String())
	}
	return out
}

// Remotes are the endpoints to resolve and pin (via direct).
func (c *WGConfig) Remotes() []Remote {
	var out []Remote
	for _, p := range c.Peers {
		out = append(out, p.Endpoint)
	}
	return out
}

// UAPI renders the device configuration for wireguard-go's IpcSet. The
// endpoints are given resolved (the addresses the pins cover), in peer order.
// Every value comes from the parsed config — keys as hex, addresses as
// parsed — so nothing in the file can add a line of its own.
func (c *WGConfig) UAPI(endpoints []netip.AddrPort) (string, error) {
	if len(endpoints) != len(c.Peers) {
		return "", fmt.Errorf("%d endpoints for %d peers", len(endpoints), len(c.Peers))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nreplace_peers=true\n", hex.EncodeToString(c.PrivateKey[:]))
	for i, p := range c.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey[:]))
		if p.PresharedKey != nil {
			fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(p.PresharedKey[:]))
		}
		fmt.Fprintf(&b, "endpoint=%s\n", endpoints[i])
		if p.Keepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.Keepalive)
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, a := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a)
		}
	}
	return b.String(), nil
}

// IsWireGuard reports whether text looks like a wg-quick file (for choosing
// the tunnel type on import).
func IsWireGuard(text string) bool {
	for _, l := range strings.Split(text, "\n") {
		if strings.EqualFold(strings.TrimSpace(l), "[interface]") {
			return true
		}
	}
	return false
}

func wgKey(s string) ([32]byte, error) {
	var k [32]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return k, fmt.Errorf("not a WireGuard key (32 bytes, base64)")
	}
	copy(k[:], b)
	return k, nil
}

// wgEndpoint parses "host:port" or "[v6]:port"; a literal address must be one
// a server can be at (as for OpenVPN remotes).
func wgEndpoint(s string) (Remote, error) {
	host, port, ok := strings.Cut(s, "]:")
	if strings.HasPrefix(s, "[") && ok {
		host = strings.TrimPrefix(host, "[")
	} else {
		i := strings.LastIndexByte(s, ':')
		if i <= 0 {
			return Remote{}, fmt.Errorf("endpoint %q needs host:port", s)
		}
		host, port = s[:i], s[i+1:]
		if strings.Contains(host, ":") {
			return Remote{}, fmt.Errorf("endpoint %q: an IPv6 address goes in brackets", s)
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return Remote{}, fmt.Errorf("endpoint %q has no valid port", s)
	}
	if host == "" || strings.ContainsAny(host, " \t\"'%") {
		return Remote{}, fmt.Errorf("endpoint %q has no valid host", s)
	}
	if why := checkRemoteAddr(host); why != "" {
		return Remote{}, errors.New(strings.Replace(why, "remote", "endpoint", 1))
	}
	return Remote{Host: host, Port: p, Proto: "udp"}, nil
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// hostPrefix parses a CIDR, or an address as a single-host prefix. Neither
// may carry a zone (netip.ParsePrefix refuses one).
func hostPrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("%q is not an address or CIDR", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}
