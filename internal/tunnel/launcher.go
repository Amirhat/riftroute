package tunnel

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sync"
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
	// Check reports whether connections can be started here at all.
	Check() error
	Start(spec LaunchSpec) (Process, error)
}

// ErrNoOpenVPN means the openvpn binary isn't installed.
var ErrNoOpenVPN = errors.New("OpenVPN isn't installed")

// binaryCandidates are the only places the daemon (root) runs openvpn from:
// never $PATH, which a user's environment controls.
func binaryCandidates() []string {
	if runtime.GOOS == "darwin" {
		return []string{
			"/opt/homebrew/sbin/openvpn", "/opt/homebrew/opt/openvpn/sbin/openvpn",
			"/usr/local/sbin/openvpn", "/usr/local/opt/openvpn/sbin/openvpn",
			"/opt/local/sbin/openvpn",
		}
	}
	return []string{"/usr/sbin/openvpn", "/usr/local/sbin/openvpn", "/sbin/openvpn"}
}

// InstallHint is the one-line fix for ErrNoOpenVPN on this OS.
func InstallHint() string {
	if runtime.GOOS == "darwin" {
		return "install it with: brew install openvpn"
	}
	return "install it with your package manager (e.g. sudo apt install openvpn)"
}

// FindOpenVPN returns the openvpn binary to run. A binary anyone but its
// owner can modify is refused: the daemon would run it as root.
func FindOpenVPN() (string, error) {
	for _, p := range binaryCandidates() {
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
			continue
		}
		if fi.Mode()&0o022 != 0 {
			return "", fmt.Errorf("%s is writable by other users; refusing to run it as root", p)
		}
		return p, nil
	}
	return "", fmt.Errorf("%w — %s", ErrNoOpenVPN, InstallHint())
}

// ExecLauncher runs the real openvpn binary.
type ExecLauncher struct {
	// Output receives each line openvpn prints (already redacted); may be nil.
	Output func(tunnel, line string)
}

// Check implements Launcher.
func (l *ExecLauncher) Check() error {
	_, err := FindOpenVPN()
	return err
}

// Start implements Launcher.
func (l *ExecLauncher) Start(spec LaunchSpec) (Process, error) {
	bin, err := FindOpenVPN()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, "--config", spec.Config)
	// openvpn execs ifconfig/route (script-security 1 allows only those); give
	// it the system paths rather than the daemon's inherited environment.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	ownProcessGroup(cmd)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		return nil, fmt.Errorf("start openvpn: %w", err)
	}
	p := &execProcess{cmd: cmd, done: make(chan struct{})}
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			ln := redactLine(sc.Text())
			p.push(ln)
			if l.Output != nil {
				l.Output(spec.Name, ln)
			}
		}
	}()
	go func() {
		p.err = cmd.Wait()
		_ = pw.Close()
		close(p.done)
	}()
	return p, nil
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
