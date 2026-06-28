// Package flow lists active connections and (via the engine) correlates each to
// the route/interface that carries it, so the user can answer "is this actually
// going through the tunnel?" (spec §7.4). Read-only: it parses ss (Linux) and
// lsof (macOS); the parsers are pure and unit-tested.
package flow

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Conn is a raw parsed connection (before route correlation).
type Conn struct {
	Proto   string
	Local   string
	Remote  string
	State   string
	Process string
}

// Collect lists active connections on the current OS.
func Collect(ctx context.Context) ([]Conn, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	switch runtime.GOOS {
	case "linux":
		out, err := exec.CommandContext(cctx, "ss", "-tunpH").Output()
		if err != nil {
			return nil, err
		}
		return ParseSS(string(out)), nil
	case "darwin":
		out, err := exec.CommandContext(cctx, "lsof", "-nP", "-iTCP", "-iUDP").Output()
		if err != nil {
			return nil, err
		}
		return ParseLsof(string(out)), nil
	default:
		return nil, nil
	}
}

// ParseSS parses `ss -tunpH` output (Linux).
// e.g. `tcp ESTAB 0 0 192.168.1.50:54321 1.2.3.4:443 users:(("firefox",pid=1,fd=4))`
func ParseSS(out string) []Conn {
	var conns []Conn
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		c := Conn{
			Proto:  f[0],
			State:  f[1],
			Local:  f[4],
			Remote: f[5],
		}
		if c.Proto == "udp" {
			c.State = ""
		}
		for _, tok := range f[6:] {
			if strings.HasPrefix(tok, "users:") {
				c.Process = procFromUsers(tok)
			}
		}
		conns = append(conns, c)
	}
	return conns
}

func procFromUsers(s string) string {
	// users:(("firefox",pid=1,fd=4))
	i := strings.Index(s, "\"")
	if i < 0 {
		return ""
	}
	rest := s[i+1:]
	j := strings.Index(rest, "\"")
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// ParseLsof parses `lsof -nP -iTCP -iUDP` output (macOS).
// e.g. `firefox 1 amir 4u IPv4 0x1 0t0 TCP 192.168.1.50:54321->1.2.3.4:443 (ESTABLISHED)`
func ParseLsof(out string) []Conn {
	var conns []Conn
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 9 || (f[7] != "TCP" && f[7] != "UDP") {
			continue
		}
		name := f[8]
		proto := strings.ToLower(f[7])
		state := ""
		if len(f) >= 10 {
			state = strings.Trim(f[9], "()")
		}
		local, remote := name, ""
		if i := strings.Index(name, "->"); i >= 0 {
			local, remote = name[:i], name[i+2:]
		}
		if remote == "" {
			continue // listening socket, nothing to correlate
		}
		conns = append(conns, Conn{Proto: proto, Local: local, Remote: remote, State: state, Process: f[0]})
	}
	return conns
}

// RemoteIP extracts the host part of a "host:port" remote (handles IPv6 [..]:p).
func RemoteIP(remote string) string {
	if remote == "" {
		return ""
	}
	if strings.HasPrefix(remote, "[") {
		if i := strings.Index(remote, "]"); i >= 0 {
			return remote[1:i]
		}
	}
	if i := strings.LastIndex(remote, ":"); i >= 0 {
		return remote[:i]
	}
	return remote
}
