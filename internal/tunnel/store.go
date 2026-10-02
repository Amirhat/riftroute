package tunnel

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// def is a stored tunnel definition. It holds secrets (the password, and any
// private key in the profile), so definitions live in their own 0600 files in
// a 0700 directory — not in the SQLite store, which is world-readable.
type def struct {
	Name        string            `json:"name"`
	Type        domain.TunnelType `json:"type"`
	Config      string            `json:"config"` // inlined profile text, re-sanitized on every load
	Username    string            `json:"username,omitempty"`
	Password    string            `json:"password,omitempty"`
	Via         domain.TunnelVia  `json:"via"`
	Routes      []string          `json:"routes"`
	AutoConnect bool              `json:"auto_connect"`
	// WhenDown is block or fallback; empty (a definition from before it) is
	// fallback.
	WhenDown  domain.TunnelWhenDown `json:"when_down,omitempty"`
	UpdatedAt time.Time             `json:"updated_at"`
}

// blocks reports whether the tunnel refuses its destinations while it's
// down.
func (d *def) blocks() bool { return d != nil && d.WhenDown == domain.TunnelBlock }

var reName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ValidName reports whether s is a usable tunnel name (it names files).
func ValidName(s string) bool { return reName.MatchString(s) }

// defStore persists definitions as <dir>/<name>.json.
type defStore struct{ dir string }

func openDefStore(dir string) (*defStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("tunnel dir: %w", err)
	}
	// MkdirAll leaves an existing directory's mode alone; secrets need 0700.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("tunnel dir: %w", err)
	}
	return &defStore{dir: dir}, nil
}

func (s *defStore) path(name string) string { return filepath.Join(s.dir, name+".json") }

// scan returns every readable definition, sorted by name, and — separately —
// the ones that can't be read or decoded, by tunnel name. One bad file must
// not take the rest down with it: the daemon (routing, the kill switch)
// starts without that tunnel instead of refusing to start at all. err is only
// for a directory that can't be read; logging the broken ones is the
// caller's job.
func (s *defStore) scan() (defs []*def, broken map[string]error, err error) {
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, nil, err
	}
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !ValidName(name) {
			continue
		}
		d, err := s.get(name)
		if err != nil {
			if broken == nil {
				broken = map[string]error{}
			}
			broken[name] = err
			continue
		}
		defs = append(defs, d)
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].Name < defs[j].Name })
	return defs, broken, nil
}

func (s *defStore) get(name string) (*def, error) {
	data, err := os.ReadFile(s.path(name))
	if err != nil {
		return nil, err
	}
	var d def
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	d.Name = name
	return &d, nil
}

// put writes atomically: a temp file (0600 from creation) renamed over the old.
func (s *defStore) put(d *def) error {
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, ".tmp-"+d.Name+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, s.path(d.Name))
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

func (s *defStore) remove(name string) error {
	_ = os.Remove(s.loginPath(name))
	err := os.Remove(s.path(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// loginPath holds the fingerprint of the tunnel's login that last connected
// (a hash of its profile, username and password — never the password), so
// a rejection of the same login after a reconnect or a restart is taken for
// the server's trouble (ikeSession.loginWorked). A file of its own: the
// definition is the user's to change, and this must never race a Save.
func (s *defStore) loginPath(name string) string { return filepath.Join(s.dir, name+".login") }

func (s *defStore) getLogin(name string) string {
	b, err := os.ReadFile(s.loginPath(name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (s *defStore) putLogin(name, print string) error {
	tmp := s.loginPath(name) + ".tmp"
	if err := os.WriteFile(tmp, []byte(print+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.loginPath(name))
}
