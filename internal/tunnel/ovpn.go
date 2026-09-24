// Package tunnel runs VPN connections for the daemon — today OpenVPN, through
// the system `openvpn` binary — as split tunnels RiftRoute routes into. The
// connection itself never touches routing or DNS: every route- and DNS-changing
// directive is removed from the profile and `route-noexec` is forced, so the
// engine installs exactly the destinations the user listed through the Apply
// Protocol, and a VPN that already owns the default route (Windscribe, …)
// keeps it.
//
// openvpn runs as root with a user-supplied profile, so the profile is parsed
// against an ALLOWLIST of client directives: anything that runs a program,
// loads a library, or reads/writes a path on the daemon's side is refused,
// and unknown directives are refused too.
package tunnel

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Remote is one `remote` entry of a profile.
type Remote struct {
	Host  string `json:"host"`
	Port  int    `json:"port"`
	Proto string `json:"proto"` // udp | tcp (normalized)
}

func (r Remote) String() string { return fmt.Sprintf("%s:%d/%s", r.Host, r.Port, r.Proto) }

// Profile is a sanitized OpenVPN client profile.
type Profile struct {
	lines   []line // allowed directives + inline blocks, in file order
	Remotes []Remote
	// NeedsAuth reports an `auth-user-pass` directive: openvpn will ask the
	// daemon (over the management socket) for a username and password.
	NeedsAuth bool
	// InlineUser/InlinePass come from an inline <auth-user-pass> block; the
	// block itself is never rendered.
	InlineUser, InlinePass string
	// Ignored lists the directives removed because RiftRoute owns their job
	// (routes, DNS, privilege settings), deduplicated and sorted.
	Ignored []string
	// verb is the profile's log level, clamped to 3–5 at render: enough for
	// diagnosis, never the packet dumps (with key material) of 7+.
	verb int
}

type line struct {
	name   string
	args   []string
	block  bool   // an inline <name> block
	body   string // the block's content
	remote bool   // a `remote` line, re-rendered from the resolved Remotes
}

// ProfileError reports why a profile was refused.
type ProfileError struct {
	Line int
	Msg  string
}

func (e *ProfileError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
	}
	return e.Msg
}

// policy is how the sanitizer treats a directive.
type policy int

const (
	keep   policy = iota // render as parsed
	ignore               // drop, and report it in Ignored
	inline               // key/cert material: inline form only
)

// directives is the allowlist. Anything absent is refused.
var directives = map[string]policy{
	// connection
	"client": keep, "tls-client": keep, "pull": keep, "nobind": keep, "float": keep,
	"resolv-retry": keep, "connect-retry": keep, "connect-retry-max": keep,
	"connect-timeout": keep, "server-poll-timeout": keep, "remote-random": keep,
	"remote-random-hostname": keep, "explicit-exit-notify": keep,
	"persist-key": keep, "persist-tun": keep, "persist-remote-ip": keep, "persist-local-ip": keep,
	"topology": keep, "tun-ipv6": keep, "push-peer-info": keep, "fast-io": keep,
	// TLS / crypto
	"remote-cert-tls": keep, "ns-cert-type": keep, "remote-cert-eku": keep, "remote-cert-ku": keep,
	"verify-x509-name": keep, "tls-version-min": keep, "tls-version-max": keep,
	"tls-cipher": keep, "tls-ciphersuites": keep, "tls-groups": keep, "tls-cert-profile": keep,
	"key-direction": keep, "cipher": keep, "data-ciphers": keep, "data-ciphers-fallback": keep,
	"ncp-ciphers": keep, "auth": keep,
	// removed from openvpn 2.6; harmless to drop
	"keysize": ignore, "ncp-disable": ignore, "key-method": ignore,
	"tls-timeout": keep, "hand-window": keep, "tran-window": keep, "tls-exit": keep,
	"reneg-sec": keep, "reneg-bytes": keep, "reneg-pkts": keep, "replay-window": keep,
	"mute-replay-warnings": keep, "auth-nocache": keep,
	// link
	"comp-lzo": keep, "compress": keep, "allow-compression": keep,
	"tun-mtu": keep, "link-mtu": keep, "mssfix": keep, "fragment": keep, "tun-mtu-extra": keep,
	"mtu-disc": keep, "sndbuf": keep, "rcvbuf": keep, "txqueuelen": keep,
	"ping": keep, "ping-restart": keep, "ping-exit": keep, "ping-timer-rem": keep,
	"keepalive": keep, "inactive": keep,
	// logging (to the daemon's pipe only — no file options)
	"verb": keep, "mute": keep,
	// RiftRoute owns routing and DNS: the tunnel must not change either.
	"redirect-gateway": ignore, "redirect-private": ignore, "route": ignore, "route-ipv6": ignore,
	"route-gateway": ignore, "route-metric": ignore, "route-delay": ignore, "route-method": ignore,
	"route-nopull": ignore, "route-noexec": ignore, "pull-filter": ignore, "dhcp-option": ignore,
	"dns": ignore, "block-outside-dns": ignore, "register-dns": ignore, "block-ipv6": ignore,
	"ip-win32": ignore, "dhcp-renew": ignore, "dhcp-release": ignore,
	// RiftRoute runs openvpn itself.
	"user": ignore, "group": ignore, "auth-retry": ignore, "setenv": ignore, "setenv-safe": ignore,
	"ignore-unknown-option": ignore, "echo": ignore,
	// key material: accepted only inline (a path would be read by root)
	"ca": inline, "cert": inline, "key": inline, "tls-auth": inline, "tls-crypt": inline,
	"tls-crypt-v2": inline, "pkcs12": inline, "extra-certs": inline, "crl-verify": inline,
	"peer-fingerprint": inline,
}

// refused explains the directives that are deliberately not allowed.
var refused = map[string]string{
	"up": "runs a script", "down": "runs a script", "up-restart": "runs a script",
	"down-pre": "runs a script", "route-up": "runs a script", "route-pre-down": "runs a script",
	"ipchange": "runs a script", "tls-verify": "runs a script", "auth-user-pass-verify": "runs a script",
	"client-connect": "runs a script", "client-disconnect": "runs a script", "learn-address": "runs a script",
	"script-security": "enables scripts", "plugin": "loads a library", "engine": "loads a library",
	"providers": "loads a library", "pkcs11-providers": "loads a library", "iproute": "runs a program",
	"config": "reads another file", "cd": "changes directory", "chroot": "changes root",
	"daemon": "detaches the process", "log": "writes a file", "log-append": "writes a file",
	"status": "writes a file", "writepid": "writes a file", "tmp-dir": "writes files",
	"askpass": "reads a file", "dev-node": "opens a device path",
	"secret": "static-key tunnels aren't supported", "static-challenge": "challenge/response logins aren't supported yet",
	"http-proxy": "proxies aren't supported yet", "socks-proxy": "proxies aren't supported yet",
	"ifconfig": "static tunnel addressing isn't supported", "ifconfig-ipv6": "static tunnel addressing isn't supported",
	"connection": "<connection> blocks aren't supported yet",
}

var (
	reHost        = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	reDevTun      = regexp.MustCompile(`^u?tun[0-9]*$`)
	reFingerprint = regexp.MustCompile(`^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){19,63}$`)
)

// allFingerprints reports whether every arg is a hex SHA fingerprint
// (`peer-fingerprint` accepts several, separated by spaces or ';').
func allFingerprints(args []string) bool {
	for _, a := range args {
		for _, f := range strings.Split(a, ";") {
			if f != "" && !reFingerprint.MatchString(f) {
				return false
			}
		}
	}
	return true
}

const maxProfileBytes = 256 << 10

// Parse sanitizes an OpenVPN client profile. File references must already be
// inlined (see InlineFiles); the result renders to a config safe to hand to a
// root openvpn process.
func Parse(text string) (*Profile, error) {
	if len(text) > maxProfileBytes {
		return nil, &ProfileError{Msg: fmt.Sprintf("profile is larger than %d KiB", maxProfileBytes>>10)}
	}
	if strings.ContainsRune(text, 0) {
		return nil, &ProfileError{Msg: "profile contains a NUL byte"}
	}
	p := &Profile{}
	ignored := map[string]bool{}
	var (
		defPort  = 1194
		defProto = "udp"
		remotes  []struct {
			ln   int
			args []string
		}
		sawDev bool
	)
	rows := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i := 0; i < len(rows); i++ {
		ln := i + 1
		raw := strings.TrimSpace(rows[i])
		if raw == "" || raw[0] == '#' || raw[0] == ';' {
			continue
		}
		// Inline block: <tag> … </tag>
		if strings.HasPrefix(raw, "<") && strings.HasSuffix(raw, ">") && !strings.HasPrefix(raw, "</") {
			tag := raw[1 : len(raw)-1]
			var body []string
			closed := false
			for i++; i < len(rows); i++ {
				if strings.TrimSpace(rows[i]) == "</"+tag+">" {
					closed = true
					break
				}
				body = append(body, rows[i])
			}
			if !closed {
				return nil, &ProfileError{Line: ln, Msg: fmt.Sprintf("<%s> is never closed", tag)}
			}
			for _, b := range body {
				if strings.HasPrefix(strings.TrimSpace(b), "</") {
					return nil, &ProfileError{Line: ln, Msg: fmt.Sprintf("<%s> block looks malformed", tag)}
				}
			}
			content := strings.Join(body, "\n")
			switch {
			case tag == "auth-user-pass":
				ls := strings.Split(strings.TrimSpace(content), "\n")
				p.InlineUser = strings.TrimSpace(ls[0])
				if len(ls) > 1 {
					p.InlinePass = strings.TrimSpace(ls[1])
				}
				p.NeedsAuth = true
			case directives[tag] == inline:
				if strings.TrimSpace(content) == "" {
					return nil, &ProfileError{Line: ln, Msg: fmt.Sprintf("<%s> block is empty", tag)}
				}
				p.lines = append(p.lines, line{name: tag, block: true, body: content})
			case refused[tag] != "":
				return nil, &ProfileError{Line: ln, Msg: fmt.Sprintf("<%s>: %s", tag, refused[tag])}
			default:
				return nil, &ProfileError{Line: ln, Msg: fmt.Sprintf("unsupported inline block <%s>", tag)}
			}
			continue
		}
		toks, err := tokenize(raw)
		if err != nil {
			return nil, &ProfileError{Line: ln, Msg: err.Error()}
		}
		if len(toks) == 0 {
			continue
		}
		name := strings.TrimPrefix(toks[0], "--")
		args := toks[1:]
		if strings.HasPrefix(name, "management") {
			return nil, &ProfileError{Line: ln, Msg: fmt.Sprintf("%s: RiftRoute manages the openvpn process itself", name)}
		}
		if why, ok := refused[name]; ok {
			return nil, &ProfileError{Line: ln, Msg: fmt.Sprintf("%s is not allowed: %s", name, why)}
		}
		switch name {
		case "verb":
			if n, err := strconv.Atoi(strings.Join(args, "")); err == nil {
				p.verb = n
			}
			continue // rendered in RiftRoute's block
		case "dev":
			if len(args) != 1 || !reDevTun.MatchString(args[0]) {
				return nil, &ProfileError{Line: ln, Msg: "only `dev tun` is supported (TAP/layer-2 tunnels are not)"}
			}
			sawDev = true
			p.lines = append(p.lines, line{name: "dev", args: []string{"tun"}})
			continue
		case "dev-type":
			if len(args) != 1 || args[0] != "tun" {
				return nil, &ProfileError{Line: ln, Msg: "only `dev-type tun` is supported"}
			}
			continue // implied by `dev tun`
		case "proto":
			pr, ok := normProto(args)
			if !ok {
				return nil, &ProfileError{Line: ln, Msg: fmt.Sprintf("unsupported proto %q", strings.Join(args, " "))}
			}
			defProto = pr
			continue // folded into each rendered remote
		case "port", "rport":
			n, ok := parsePort(args)
			if !ok {
				return nil, &ProfileError{Line: ln, Msg: fmt.Sprintf("invalid %s", name)}
			}
			defPort = n
			continue
		case "lport", "bind":
			continue // the client never needs a fixed local port
		case "remote":
			remotes = append(remotes, struct {
				ln   int
				args []string
			}{ln, args})
			p.lines = append(p.lines, line{name: "remote", remote: true})
			continue
		case "auth-user-pass":
			// A path argument would be read by root; credentials come over the
			// management socket instead (see Manager).
			p.NeedsAuth = true
			p.lines = append(p.lines, line{name: "auth-user-pass"})
			continue
		}
		switch pol, ok := directives[name]; {
		case !ok:
			return nil, &ProfileError{Line: ln, Msg: fmt.Sprintf("unsupported directive %q", name)}
		case pol == ignore:
			ignored[name] = true
		case name == "peer-fingerprint" && len(args) > 0 && allFingerprints(args):
			// The value form (`peer-fingerprint AA:BB:…`) names no file.
			p.lines = append(p.lines, line{name: name, args: args})
		case pol == inline:
			// `tls-auth [inline] 1` is fine; `ca /path/ca.crt` is not.
			if len(args) > 0 && args[0] != "[inline]" {
				return nil, &ProfileError{Line: ln, Msg: fmt.Sprintf("%s refers to a file; inline it (riftroute tunnel add does this for you)", name)}
			}
			if name == "tls-auth" && len(args) == 2 {
				if args[1] != "0" && args[1] != "1" {
					return nil, &ProfileError{Line: ln, Msg: "tls-auth key direction must be 0 or 1"}
				}
				p.lines = append(p.lines, line{name: "key-direction", args: args[1:]})
			}
		default:
			if err := checkArgs(args); err != nil {
				return nil, &ProfileError{Line: ln, Msg: fmt.Sprintf("%s: %v", name, err)}
			}
			p.lines = append(p.lines, line{name: name, args: args})
		}
	}
	for _, r := range remotes {
		if len(r.args) == 0 || len(r.args) > 3 || !(IsAddr(r.args[0]) || reHost.MatchString(r.args[0])) {
			return nil, &ProfileError{Line: r.ln, Msg: "remote needs a host name or IP"}
		}
		rem := Remote{Host: r.args[0], Port: defPort, Proto: defProto}
		if len(r.args) > 1 {
			n, ok := parsePort(r.args[1:2])
			if !ok {
				return nil, &ProfileError{Line: r.ln, Msg: fmt.Sprintf("invalid remote port %q", r.args[1])}
			}
			rem.Port = n
		}
		if len(r.args) > 2 {
			pr, ok := normProto(r.args[2:])
			if !ok {
				return nil, &ProfileError{Line: r.ln, Msg: fmt.Sprintf("unsupported remote proto %q", r.args[2])}
			}
			rem.Proto = pr
		}
		p.Remotes = append(p.Remotes, rem)
	}
	if len(p.Remotes) == 0 {
		return nil, &ProfileError{Msg: "profile has no `remote` server"}
	}
	if !sawDev {
		p.lines = append([]line{{name: "dev", args: []string{"tun"}}}, p.lines...)
	}
	for k := range ignored {
		p.Ignored = append(p.Ignored, k)
	}
	sort.Strings(p.Ignored)
	return p, nil
}

// RenderOptions are the runtime values a rendered config needs.
type RenderOptions struct {
	// Remotes replace the profile's remotes (e.g. resolved to the addresses
	// the bypass routes pin). Empty keeps the profile's own.
	Remotes []Remote
	// Management is the unix socket openvpn listens on for the daemon.
	Management string
}

// Render produces the config handed to openvpn: the allowed directives, then
// RiftRoute's fixed block. Later single-value options override earlier ones,
// and pull-filters match first-wins, so the fixed block always prevails.
func (p *Profile) Render(o RenderOptions) string {
	var b strings.Builder
	b.WriteString("# Generated by riftrouted. Routes and DNS are managed by RiftRoute.\n")
	remotes := o.Remotes
	if len(remotes) == 0 {
		remotes = p.Remotes
	}
	wroteRemotes := false
	for _, l := range p.lines {
		switch {
		case l.remote:
			if wroteRemotes {
				continue
			}
			wroteRemotes = true
			for _, r := range remotes {
				fmt.Fprintf(&b, "remote %s %d %s\n", r.Host, r.Port, r.Proto)
			}
		case l.block:
			fmt.Fprintf(&b, "<%s>\n%s\n</%s>\n", l.name, strings.Trim(l.body, "\n"), l.name)
		default:
			b.WriteString(l.name)
			for _, a := range l.args {
				b.WriteByte(' ')
				b.WriteString(quote(a))
			}
			b.WriteByte('\n')
		}
	}
	b.WriteString(p.cipherCompat())
	b.WriteString(`# --- RiftRoute ---
route-nopull
route-noexec
pull-filter ignore "redirect-gateway"
pull-filter ignore "redirect-private"
pull-filter ignore "dhcp-option"
pull-filter ignore "dns"
pull-filter ignore "block-outside-dns"
pull-filter ignore "register-dns"
script-security 1
persist-tun
auth-nocache
auth-retry none
`)
	fmt.Fprintf(&b, "verb %d\n", min(max(p.verb, 3), 5))
	fmt.Fprintf(&b, "management %s unix\nmanagement-hold\nmanagement-query-passwords\n", quote(o.Management))
	return b.String()
}

// defaultDataCiphers is openvpn 2.6+'s built-in --data-ciphers.
const defaultDataCiphers = "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"

// cipherCompat keeps a profile's `cipher` usable. openvpn 2.6+ ignores
// `cipher` when negotiating and offers only defaultDataCiphers, so a server
// that speaks just the profile's cipher (older OpenVPN, MikroTik) finds no
// common one and hangs up after the login. OpenVPN Connect offers the CBC
// ciphers too, so profiles written for it assume this: offer the profile's
// cipher and fall back to it for servers that don't negotiate at all.
func (p *Profile) cipherCompat() string {
	var cipher string
	hasList, hasFallback := false, false
	for _, l := range p.lines {
		switch l.name {
		case "cipher":
			if len(l.args) == 1 {
				cipher = l.args[0]
			}
		case "data-ciphers", "ncp-ciphers":
			hasList = true // the profile chose its own list
		case "data-ciphers-fallback":
			hasFallback = true
		}
	}
	// BF-CBC is missing from OpenSSL 3, where naming it stops openvpn from
	// starting; "none" is never offered.
	if cipher == "" || strings.EqualFold(cipher, "none") || strings.EqualFold(cipher, "BF-CBC") {
		return ""
	}
	var b strings.Builder
	if !hasList {
		list := defaultDataCiphers
		if !slices.ContainsFunc(strings.Split(list, ":"), func(c string) bool { return strings.EqualFold(c, cipher) }) {
			list += ":" + cipher
		}
		fmt.Fprintf(&b, "data-ciphers %s\n", quote(list))
	}
	if !hasFallback {
		fmt.Fprintf(&b, "data-ciphers-fallback %s\n", quote(cipher))
	}
	return b.String()
}

// Servers returns the remotes as "host:port/proto" strings.
func (p *Profile) Servers() []string {
	out := make([]string, 0, len(p.Remotes))
	for _, r := range p.Remotes {
		out = append(out, r.String())
	}
	return out
}

// tokenize splits a config line like openvpn does: whitespace-separated,
// "double quotes" with backslash escapes, 'single quotes' literal, and an
// unquoted token starting with # or ; ends the line.
func tokenize(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inTok := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c < 0x20 && c != '\t' || c == 0x7f:
			return nil, fmt.Errorf("control character in line")
		case c == ' ' || c == '\t':
			if inTok {
				out = append(out, cur.String())
				cur.Reset()
				inTok = false
			}
		case (c == '#' || c == ';') && !inTok:
			return out, nil
		case c == '"':
			inTok = true
			for i++; ; i++ {
				if i >= len(s) {
					return nil, fmt.Errorf("unterminated quote")
				}
				if s[i] == '\\' && i+1 < len(s) {
					i++
					cur.WriteByte(s[i])
					continue
				}
				if s[i] == '"' {
					break
				}
				cur.WriteByte(s[i])
			}
		case c == '\'':
			inTok = true
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, fmt.Errorf("unterminated quote")
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
		case c == '\\' && i+1 < len(s):
			inTok = true
			i++
			cur.WriteByte(s[i])
		default:
			inTok = true
			cur.WriteByte(c)
		}
	}
	if inTok {
		out = append(out, cur.String())
	}
	return out, nil
}

// quote renders a token so tokenize (and openvpn) read it back unchanged.
func quote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'\\#;") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

func checkArgs(args []string) error {
	for _, a := range args {
		if len(a) > 512 {
			return fmt.Errorf("argument too long")
		}
	}
	return nil
}

func parsePort(args []string) (int, bool) {
	if len(args) != 1 {
		return 0, false
	}
	n, err := strconv.Atoi(args[0])
	return n, err == nil && n > 0 && n < 65536
}

// normProto maps openvpn's proto spellings to udp|tcp (the family suffixes
// and -client are client-side synonyms; RiftRoute pins the family itself).
func normProto(args []string) (string, bool) {
	if len(args) != 1 {
		return "", false
	}
	switch args[0] {
	case "udp", "udp4", "udp6":
		return "udp", true
	case "tcp", "tcp4", "tcp6", "tcp-client", "tcp4-client", "tcp6-client":
		return "tcp", true
	}
	return "", false
}

// IsAddr reports whether host is an IP literal (no resolution needed).
func IsAddr(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}
