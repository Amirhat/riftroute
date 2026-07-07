// Package sysinfo enumerates local users and application units so the GUI can
// offer searchable pickers for per-app routing instead of free-text entry.
// macOS PF matches per-app traffic by socket owner (uid/username), so the
// picker lists users; Linux matches by cgroup v2 path, so it lists service/
// scope/slice units from the unified hierarchy. Read-only; parsing is pure and
// unit-tested, host reads are thin.
package sysinfo

import (
	"bufio"
	"context"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// User is a local account that can own sockets (macOS PF `user` selector).
type User struct {
	UID      string `json:"uid"`
	Username string `json:"username"`
	FullName string `json:"full_name,omitempty"`
}

// App is a per-app routing target: on Linux, a cgroup v2 path relative to the
// unified hierarchy (what nft's `socket cgroupv2` matches).
type App struct {
	Value string `json:"value"` // the rule value (cgroup path)
	Name  string `json:"name"`  // human-readable unit name
}

// Users lists real local accounts. macOS asks Directory Services (local
// accounts live there, not in /etc/passwd); everywhere else /etc/passwd.
func Users(ctx context.Context) ([]User, error) {
	if runtime.GOOS == "darwin" {
		if us, err := darwinUsers(ctx); err == nil && len(us) > 0 {
			return us, nil
		}
	}
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}
	return ParsePasswd(string(b), minRealUID()), nil
}

// Apps lists per-app routing targets. Linux-only (cgroup v2); empty elsewhere.
func Apps(context.Context) ([]App, error) {
	if runtime.GOOS != "linux" {
		return []App{}, nil
	}
	return CgroupApps(os.DirFS("/sys/fs/cgroup")), nil
}

func minRealUID() int {
	if runtime.GOOS == "darwin" {
		return 500
	}
	return 1000
}

func darwinUsers(ctx context.Context) ([]User, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "dscl", ".", "-list", "/Users", "UniqueID").Output()
	if err != nil {
		return nil, err
	}
	names := map[string]string{} // username → full name (best-effort)
	if rn, err := exec.CommandContext(cctx, "dscl", ".", "-list", "/Users", "RealName").Output(); err == nil {
		names = parseDsclPairs(string(rn))
	}
	return ParseDsclUsers(string(out), names, minRealUID()), nil
}

// ParseDsclUsers parses `dscl . -list /Users UniqueID` output ("name  uid" per
// line), keeping root and real accounts (uid ≥ minUID, no "_" service prefix).
func ParseDsclUsers(out string, fullNames map[string]string, minUID int) []User {
	var users []User
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		name, uid := f[0], f[len(f)-1]
		if !keepUser(name, uid, minUID) {
			continue
		}
		users = append(users, User{UID: uid, Username: name, FullName: fullNames[name]})
	}
	sortUsers(users)
	return users
}

// parseDsclPairs parses `dscl . -list /Users RealName` ("name  Real Name…").
func parseDsclPairs(out string) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		m[f[0]] = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), f[0]))
	}
	return m
}

// ParsePasswd parses /etc/passwd, keeping root and real accounts.
func ParsePasswd(content string, minUID int) []User {
	var users []User
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 5 {
			continue
		}
		name, uid, gecos := f[0], f[2], f[4]
		if !keepUser(name, uid, minUID) {
			continue
		}
		full := strings.SplitN(gecos, ",", 2)[0]
		users = append(users, User{UID: uid, Username: name, FullName: full})
	}
	sortUsers(users)
	return users
}

func keepUser(name, uid string, minUID int) bool {
	if strings.HasPrefix(name, "_") || name == "nobody" || name == "daemon" {
		return false
	}
	n, err := strconv.Atoi(uid)
	if err != nil {
		return false
	}
	return n == 0 || n >= minUID
}

func sortUsers(users []User) {
	sort.Slice(users, func(i, j int) bool {
		a, _ := strconv.Atoi(users[i].UID)
		b, _ := strconv.Atoi(users[j].UID)
		if a != b {
			return a < b
		}
		return users[i].Username < users[j].Username
	})
}

const maxApps = 500

// CgroupApps walks a cgroup v2 hierarchy and returns service/scope units —
// the paths nft's `socket cgroupv2` matcher accepts. Depth- and count-capped;
// takes an fs.FS so tests use fstest.MapFS.
func CgroupApps(fsys fs.FS) []App {
	var apps []App
	_ = fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() || path == "." {
			return nil
		}
		if strings.Count(path, "/") > 3 {
			return fs.SkipDir
		}
		base := d.Name()
		if strings.HasSuffix(base, ".service") || strings.HasSuffix(base, ".scope") {
			name := strings.TrimSuffix(strings.TrimSuffix(base, ".service"), ".scope")
			// Session scopes render as-is; app scopes like app-firefox-1234.scope
			// keep their middle segment as the friendly name.
			if strings.HasPrefix(name, "app-") {
				parts := strings.Split(name, "-")
				if len(parts) >= 2 {
					name = parts[1]
				}
			}
			apps = append(apps, App{Value: path, Name: name})
			if len(apps) >= maxApps {
				return fs.SkipAll
			}
		}
		return nil
	})
	sort.Slice(apps, func(i, j int) bool { return apps[i].Name < apps[j].Name })
	return apps
}
