package tunnel

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sync"

	"github.com/Amirhat/riftroute/internal/domain"
)

// LaunchSpec is what a Launcher starts.
type LaunchSpec struct {
	Name       string   // tunnel name, for logs
	Config     string   // path of the rendered config
	Management string   // the management socket the config names
	Profile    *Profile // the sanitized profile (the fake reads NeedsAuth)
}

// Process is a running openvpn.
type Process interface {
	Pid() int
	// Wait blocks until the process exits.
	Wait() error
	// Kill ends it without a clean shutdown (a SIGTERM over the management
	// socket is the normal path).
	Kill() error
	// Tail returns the last lines it printed, for error reports.
	Tail() []string
}

// Launcher starts openvpn processes.
type Launcher interface {
	// Engine reports whether connections can be started here at all, and
	// if not, how the user installs what's missing.
	Engine() domain.TunnelEngine
	Start(spec LaunchSpec) (Process, error)
}

// ExecLauncher runs the real openvpn binary — only one findOpenVPN accepts
// (binary.go): on macOS the one that ships with RiftRoute, on Linux the
// distribution's, root-owned all the way up.
type ExecLauncher struct {
	// Output receives each line openvpn prints (already redacted); may be nil.
	Output func(tunnel, line string)
	vc     versionCache
}

// Engine implements Launcher. It looks again on every call, so openvpn
// installed while the daemon runs is picked up without a restart.
func (l *ExecLauncher) Engine() domain.TunnelEngine {
	e, _ := l.engine()
	return e
}

// engine is Engine plus the file that was checked, for Start's last look.
func (l *ExecLauncher) engine() (domain.TunnelEngine, fs.FileInfo) {
	bin, fi, err := findOpenVPN()
	e := detectEngine(readHost(), func() (string, os.FileInfo, error) { return bin, fi, err }, l.vc.version)
	return e, fi
}

// Start implements Launcher.
func (l *ExecLauncher) Start(spec LaunchSpec) (Process, error) {
	e, fi := l.engine()
	if !e.Available {
		return nil, &EngineError{Engine: e}
	}
	if err := sameFileAsChecked(e.Path, fi); err != nil {
		return nil, err
	}
	cmd := exec.Command(e.Path, "--config", spec.Config)
	// Nothing from the daemon's environment: see openvpnEnv.
	cmd.Env = openvpnEnv(runtime.GOOS)
	ownProcessGroup(cmd)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		return nil, fmt.Errorf("start openvpn: %w", err)
	}
	p := &execProcess{cmd: cmd, done: make(chan struct{})}
	go readLines(pr, maxOutputLine, func(s string) {
		ln := redactLine(s)
		p.push(ln)
		if l.Output != nil {
			l.Output(spec.Name, ln)
		}
	})
	go func() {
		p.err = cmd.Wait()
		_ = pw.Close()
		close(p.done)
	}()
	return p, nil
}

// maxOutputLine is the longest line of openvpn output kept; the rest of a
// longer one is dropped.
const maxOutputLine = 64 << 10

// readLines calls fn with each line r yields (without its line ending), cut
// to max bytes, until r ends. It always reads r to the end: if it stopped
// early (as a bufio.Scanner does on a line longer than its buffer), openvpn
// would block writing to the full pipe, and its Wait would never return.
func readLines(r io.Reader, max int, fn func(string)) {
	br := bufio.NewReader(r)
	var line []byte
	for {
		part, more, err := br.ReadLine()
		if room := max - len(line); room > 0 {
			line = append(line, part[:min(len(part), room)]...)
		}
		if err != nil { // ReadLine returns a line or an error, never both
			if len(line) > 0 {
				fn(string(line)) // the pipe closed inside a long line
			}
			_, _ = io.Copy(io.Discard, r) // ReadLine's error may not be EOF
			return
		}
		if !more {
			fn(string(line))
			line = line[:0]
		}
	}
}

type execProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
	mu   sync.Mutex
	tail []string
}

func (p *execProcess) Pid() int    { return p.cmd.Process.Pid }
func (p *execProcess) Wait() error { <-p.done; return p.err }
func (p *execProcess) Kill() error { return p.cmd.Process.Kill() }

func (p *execProcess) Tail() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.tail...)
}

func (p *execProcess) push(l string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tail = append(p.tail, l)
	if len(p.tail) > 400 { // several whole connection attempts, plus startup warnings
		p.tail = p.tail[len(p.tail)-400:]
	}
}

// reAuthToken matches a session token the server pushes (a credential).
var reAuthToken = regexp.MustCompile(`auth-token[^,'"]*`)

func redactLine(s string) string { return reAuthToken.ReplaceAllString(s, "auth-token [redacted]") }
