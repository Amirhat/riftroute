package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// event is one real-time notification from openvpn's management interface
// (">KIND:body"). Command replies (SUCCESS:/ERROR:) surface as kind "SUCCESS"
// or "ERROR" so a refused credential write is visible to the session.
type event struct {
	kind string
	body string
}

// mgmtConn is a client of openvpn's management interface over a unix socket.
type mgmtConn struct {
	conn net.Conn
	wmu  sync.Mutex
}

// dialMgmt connects to the management socket, retrying while openvpn starts.
func dialMgmt(ctx context.Context, path string) (*mgmtConn, error) {
	var d net.Dialer
	for {
		c, err := d.DialContext(ctx, "unix", path)
		if err == nil {
			return &mgmtConn{conn: c}, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("openvpn's management socket never came up: %w", err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// send writes one command line.
func (m *mgmtConn) send(cmd string) error {
	if strings.ContainsAny(cmd, "\r\n") {
		return errors.New("management command contains a newline")
	}
	m.wmu.Lock()
	defer m.wmu.Unlock()
	_ = m.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := m.conn.Write([]byte(cmd + "\n"))
	return err
}

// read delivers events until the connection closes (openvpn exited).
func (m *mgmtConn) read(fn func(event)) error {
	sc := bufio.NewScanner(m.conn)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := strings.TrimRight(sc.Text(), "\r")
		switch {
		case strings.HasPrefix(l, ">"):
			kind, body, _ := strings.Cut(l[1:], ":")
			fn(event{kind: kind, body: body})
		case strings.HasPrefix(l, "SUCCESS:"):
			fn(event{kind: "SUCCESS", body: strings.TrimSpace(l[len("SUCCESS:"):])})
		case strings.HasPrefix(l, "ERROR:"):
			fn(event{kind: "ERROR", body: strings.TrimSpace(l[len("ERROR:"):])})
		}
	}
	return sc.Err()
}

func (m *mgmtConn) close() error { return m.conn.Close() }

// mgmtQuote quotes a value for a management command (the same rules as the
// config parser: double quotes, backslash escapes).
func mgmtQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

// stateInfo is a parsed >STATE: notification:
// time,name,desc,local_ip,remote_ip,remote_port,local_addr,local_port,local_ipv6
type stateInfo struct {
	name, desc, localIP, remoteIP, remotePort, localIPv6 string
}

func parseState(body string) stateInfo {
	f := strings.Split(body, ",")
	at := func(i int) string {
		if i < len(f) {
			return strings.TrimSpace(f[i])
		}
		return ""
	}
	return stateInfo{name: at(1), desc: at(2), localIP: at(3), remoteIP: at(4), remotePort: at(5), localIPv6: at(8)}
}

// parseBytecount parses ">BYTECOUNT:in,out".
func parseBytecount(body string) (in, out uint64, ok bool) {
	a, b, found := strings.Cut(body, ",")
	if !found {
		return 0, 0, false
	}
	i, e1 := strconv.ParseUint(a, 10, 64)
	o, e2 := strconv.ParseUint(b, 10, 64)
	return i, o, e1 == nil && e2 == nil
}
