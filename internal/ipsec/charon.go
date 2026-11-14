package ipsec

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/strongswan/govici/vici"
)

// Charon is the one charon the daemon runs for every L2TP/IPsec tunnel.
// It's started with the first connection and stopped with the last.
type Charon struct {
	// Bin is charon (macOS: RiftRoute's own build) or charon-systemd (Linux:
	// the distribution's, which writes no PID file of its own).
	Bin string
	// Dir is its run directory (0700): strongswan.conf, the VICI socket.
	Dir string
	// GOOS picks the kernel interface (kernel-pfkey on darwin).
	GOOS string
	// Env is the rest of its environment; Prepare adjusts the command (a
	// parent-death signal, a session of its own).
	Env     []string
	Prepare func(*exec.Cmd)
	Log     *slog.Logger

	mu    sync.Mutex
	cmd   *exec.Cmd
	vs    *vici.Session
	exit  chan struct{}
	conns map[string]loaded
	// tail is its last log lines, under a lock of its own: the reader must
	// never wait for mu, or charon's output stops being drained, its exit
	// is never seen (cmd.Wait waits for it), and a Down holding mu waits
	// for that exit forever.
	tmu  sync.Mutex
	tail []string
}

type loaded struct {
	keyID string // a certificate's key (unload-key)
	psk   bool
}

// startWait bounds charon's start (its VICI socket appearing).
var startWait = 15 * time.Second

func (c *Charon) socket() string { return filepath.Join(c.Dir, "charon.vici") }

// ensure starts charon if it isn't running.
func (c *Charon) ensure(ctx context.Context) error {
	if c.cmd != nil {
		select {
		case <-c.exit:
			c.reset()
		default:
			return nil
		}
	}
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return err
	}
	stopLeftover(filepath.Join(c.Dir, "charon.pid"), c.Log)
	conf := filepath.Join(c.Dir, "strongswan.conf")
	_ = os.Remove(c.socket())
	if err := os.WriteFile(conf, []byte(Conf(c.GOOS, c.socket())), 0o600); err != nil {
		return err
	}
	cmd := exec.Command(c.Bin)
	cmd.Env = append(append([]string{}, c.Env...), "STRONGSWAN_CONF="+conf)
	cmd.Dir = c.Dir
	cmd.WaitDelay = 3 * time.Second
	if c.Prepare != nil {
		c.Prepare(cmd)
	}
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("can't start strongSwan's %s: %w", filepath.Base(c.Bin), err)
	}
	exit := make(chan struct{})
	go c.logLines(pr)
	go func() {
		err := cmd.Wait()
		_ = pw.Close()
		c.Log.Info("charon exited", "err", err)
		close(exit)
	}()
	c.cmd, c.exit, c.conns = cmd, exit, map[string]loaded{}
	deadline := time.Now().Add(startWait)
	for {
		vs, err := vici.NewSession(vici.WithSocketPath(c.socket()))
		if err == nil {
			c.vs = vs
			return nil
		}
		select {
		case <-exit:
			c.reset()
			return fmt.Errorf("strongSwan's charon stopped as it started%s", c.lastLines())
		case <-ctx.Done():
			c.stopLocked()
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			c.stopLocked()
			return errors.New("strongSwan's charon didn't start (no VICI socket)" + c.lastLines())
		}
	}
}

func (c *Charon) logLines(r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		c.Log.Debug("charon", "line", line)
		c.tmu.Lock()
		c.tail = append(c.tail, line)
		if len(c.tail) > 60 {
			c.tail = c.tail[len(c.tail)-60:]
		}
		c.tmu.Unlock()
	}
}

func (c *Charon) lastLines() string {
	c.tmu.Lock()
	defer c.tmu.Unlock()
	n := len(c.tail)
	if n == 0 {
		return ""
	}
	return ": " + strings.Join(c.tail[max(0, n-3):], " | ")
}

func (c *Charon) reset() {
	if c.vs != nil {
		_ = c.vs.Close()
	}
	c.cmd, c.vs, c.exit, c.conns = nil, nil, nil, nil
}

// stopLocked ends charon: it deletes its SAs with the servers and removes
// its policies.
func (c *Charon) stopLocked() {
	if c.cmd == nil {
		return
	}
	_ = c.cmd.Process.Signal(sigTerm)
	select {
	case <-c.exit:
	case <-time.After(5 * time.Second):
		_ = c.cmd.Process.Kill()
		<-c.exit
	}
	c.reset()
}

// stopLeftover ends a charon an earlier daemon left running (it crashed;
// on macOS nothing ended its children). Its PID file (RiftRoute's charon is
// built with its PID directory in Dir) would keep a new one from starting,
// and its policies would hold the servers' L2TP ports. Asked to stop, it
// deletes them.
func stopLeftover(pidFile string, log *slog.Logger) {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 || pid == os.Getpid() || !isCharon(pid) {
		return
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	log.Warn("stopping a charon left running", "pid", pid)
	_ = p.Signal(sigTerm)
	for range 50 {
		if !isCharon(pid) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = p.Kill()
}

// isCharon reports whether pid is a running charon.
func isCharon(pid int) bool {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	return err == nil && strings.Contains(filepath.Base(strings.TrimSpace(string(out))), "charon")
}

// Stop ends charon whatever is loaded (the daemon shutting down).
func (c *Charon) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopLocked()
}

// Up loads c's connection and brings its SA up: it returns once the
// server's L2TP port is reached only through IPsec, or with why not.
func (c *Charon) Up(ctx context.Context, conn Conn) error {
	if err := conn.check(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensure(ctx); err != nil {
		return err
	}
	if _, ok := c.conns[conn.Name]; ok {
		c.downLocked(conn.Name)
	}
	var l loaded
	if conn.PSK != "" {
		if err := c.call("load-shared", pskMessage(conn)); err != nil {
			return fmt.Errorf("ipsec: loading the shared secret: %w", err)
		}
		l.psk = true
	} else {
		km, err := keyMessage(conn)
		if err != nil {
			return err
		}
		out, err := c.vs.Call(context.Background(), "load-key", km)
		if err == nil {
			err = out.Err()
		}
		if err != nil {
			return fmt.Errorf("couldn't read the profile's private key: %w", err)
		}
		l.keyID, _ = out.Get("id").(string)
		for _, cert := range conn.Chain {
			m := vici.NewMessage()
			_ = m.Set("type", "X509")
			_ = m.Set("flag", "NONE")
			_ = m.Set("data", string(cert))
			if err := c.call("load-cert", m); err != nil {
				return fmt.Errorf("ipsec: loading an intermediate certificate: %w", err)
			}
		}
	}
	c.conns[conn.Name] = l // unloaded by Down, whatever happens next
	cm, err := connMessage(conn)
	if err != nil {
		return err
	}
	if err := c.call("load-conn", cm); err != nil {
		return fmt.Errorf("ipsec: loading the connection: %w", err)
	}
	return c.initiate(ctx, conn)
}

func (c *Charon) call(cmd string, m *vici.Message) error {
	out, err := c.vs.Call(context.Background(), cmd, m)
	if err != nil {
		return err
	}
	return out.Err()
}

// initiate starts the CHILD_SA and waits for it, reading charon's log for
// why it failed.
func (c *Charon) initiate(ctx context.Context, conn Conn) error {
	m := vici.NewMessage()
	_ = m.Set("child", child)
	_ = m.Set("ike", conn.Name)
	_ = m.Set("timeout", "30000")
	_ = m.Set("loglevel", "1")
	ictx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	var log []string
	var failed error
	for msg, err := range c.vs.CallStreaming(ictx, "initiate", "control-log", m) {
		if err != nil {
			failed = err
			break
		}
		if s, ok := msg.Get("msg").(string); ok {
			c.Log.Info("ipsec", "conn", conn.Name, "log", s)
			log = append(log, s)
			continue
		}
		if e := msg.Err(); e != nil {
			failed = e
		}
	}
	if failed == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return explain(conn, log, failed)
}

// Down terminates and unloads a connection: its SA is deleted with the
// server, its policies and secrets go. With nothing left, charon stops.
func (c *Charon) Down(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.downLocked(name)
	if len(c.conns) == 0 {
		c.stopLocked()
	}
}

func (c *Charon) downLocked(name string) {
	l, ok := c.conns[name]
	if !ok || c.vs == nil {
		return
	}
	delete(c.conns, name)
	t := vici.NewMessage()
	_ = t.Set("ike", name)
	_ = t.Set("timeout", "3000")
	for range c.vs.CallStreaming(context.Background(), "terminate", "control-log", t) {
	}
	u := vici.NewMessage()
	_ = u.Set("name", name)
	_ = c.call("unload-conn", u)
	if l.psk {
		s := vici.NewMessage()
		_ = s.Set("id", Conn{Name: name}.pskID())
		_ = c.call("unload-shared", s)
	}
	if l.keyID != "" {
		k := vici.NewMessage()
		_ = k.Set("id", l.keyID)
		_ = c.call("unload-key", k)
	}
}

// explain turns a failed initiate into what the user should know. The
// phrases are the tunnels' own (internal/tunnel failureCodes).
func explain(conn Conn, log []string, err error) error {
	all := strings.Join(log, "\n")
	has := func(s ...string) bool {
		for _, x := range s {
			if strings.Contains(all, x) {
				return true
			}
		}
		return false
	}
	switch {
	case has("NO_PROPOSAL_CHOSEN", "no acceptable proposal", "no matching proposal"):
		return lasting("IPsec: the server accepted none of the profile's encryption settings")
	case conn.PSK != "" && has("invalid HASH_V1", "decryption failed", "message parsing failed", "AUTHENTICATION_FAILED",
		"verification of AUTH payload", "no shared key found"):
		return lasting("IPsec: the server rejected the shared secret (or its identity isn't the one expected)")
	case conn.PSK == "" && has("AUTHENTICATION_FAILED", "constraint check failed", "no trusted RSA public key", "no trusted ECDSA public key"):
		if has("no trusted", "constraint check failed") {
			return lasting("IPsec: the server's certificate couldn't be verified with the profile's certificate authorities")
		}
		return lasting("IPsec: the server rejected this profile's certificate")
	case has("INVALID_ID_INFORMATION", "TS_UNACCEPTABLE", "no matching CHILD_SA config"):
		return lasting("IPsec: the server refused the L2TP connection's selectors (transport mode, UDP port 1701)")
	case has("giving up after", "retransmit", "peer not responding"):
		return errors.New("IPsec: the server didn't answer (IKE on UDP 500/4500)")
	}
	tail := log
	if len(tail) > 3 {
		tail = tail[len(tail)-3:]
	}
	if len(tail) > 0 {
		return fmt.Errorf("IPsec failed: %v (%s)", err, strings.Join(tail, " | "))
	}
	return fmt.Errorf("IPsec failed: %w", err)
}

// lastingError is an IPsec failure a retry can't fix (the key, the
// certificates, the proposals): see Lasting.
type lastingError struct{ msg string }

func (e *lastingError) Error() string { return e.msg }

func lasting(msg string) error { return &lastingError{msg} }

// LastingError is an IPsec failure a retry can't fix, for stand-ins
// (tunnel.FakeIPsec).
func LastingError(msg string) error { return lasting(msg) }

// Lasting reports whether err is an IPsec failure trying again can't fix.
func Lasting(err error) bool {
	var l *lastingError
	return errors.As(err, &l)
}
