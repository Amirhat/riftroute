package telemetry

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// The counters a report takes from the daemon's own running (the rest comes
// from what it already records: the audit log, the configuration).
const (
	KeyStarts          = "daemon.starts"
	KeyUnclean         = "daemon.unclean"
	KeyPanics          = "daemon.panics"
	KeyInstalled       = "updates.installed"
	KeyRolledBackHlth  = "updates.rolled_back_health"
	KeyRolledBackUser  = "updates.rolled_back_user"
	KeySkippedBroken   = "updates.skipped_broken"
	KeyHelpersRepaired = "updates.helpers_repaired"
	KeyCheckFailed     = "updates.check_failed"
	KeyDNSFailures     = "events.dns_failures"
)

// Tunnel session events.
const (
	TunnelConnected = "connected"
	TunnelDrop      = "drops"
	TunnelGaveUp    = "gave_up"
)

// TunnelKey is the counter for a tunnel type's session event.
func TunnelKey(tunnelType, event string) string { return "tunnel." + tunnelType + "." + event }

// FailureKey is the counter for a tunnel type's failed attempts with code.
func FailureKey(tunnelType, code string) string {
	return "tunnel." + tunnelType + ".failed." + Known(FailureCodes, code)
}

var reKey = regexp.MustCompile(`^(daemon|updates|events)\.[a-z_]+$|^tunnel\.[a-z0-9]+\.(connected|drops|gave_up|failed\.[a-z_]+)$`)

// countersFile is where they're kept, beside the database.
func countersFile(dir string) string { return filepath.Join(dir, "telemetry-counters.json") }

// Counters are counts kept across restarts until a report carries them.
// The zero value and nil discard everything (a test); so does one that's
// off (SetOn).
type Counters struct {
	on     atomic.Bool
	mu     sync.Mutex
	path   string
	counts map[string]int
	dirty  bool
}

// SetOn starts or stops counting: telemetry is on, or off. Off also
// forgets what was counted and deletes the file.
func (c *Counters) SetOn(on bool) {
	if c == nil {
		return
	}
	if c.on.Swap(on) == on {
		return
	}
	if on {
		_ = c.Keep()
	} else {
		c.Discard()
	}
}

// OpenCounters loads the counters kept in dir (none if there are none, or
// they can't be read), counting from now if on — else they're discarded.
func OpenCounters(dir string, on bool) *Counters {
	c := &Counters{path: countersFile(dir), counts: map[string]int{}}
	if !on {
		c.Discard()
		return c
	}
	c.counts = readCounts(c.path)
	c.on.Store(true)
	_ = c.Keep()
	return c
}

func readCounts(path string) map[string]int {
	out := map[string]int{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var f struct {
		Counts map[string]int `json:"counts"`
	}
	if json.Unmarshal(b, &f) != nil {
		return out
	}
	for k, n := range f.Counts {
		if reKey.MatchString(k) && n > 0 && n <= maxCount {
			out[k] = n
		}
	}
	return out
}

// Add counts n more of key. A key outside the schema is a programming
// error: it's dropped (and reported by tests through ValidKey).
func (c *Counters) Add(key string, n int) {
	if c == nil || c.path == "" || n <= 0 || !c.on.Load() || !ValidKey(key) {
		return
	}
	c.mu.Lock()
	c.counts[key] = min(c.counts[key]+n, maxCount)
	c.dirty = true
	c.mu.Unlock()
}

// Inc counts one more of key.
func (c *Counters) Inc(key string) { c.Add(key, 1) }

// ValidKey reports whether key is one a report has a place for.
func ValidKey(key string) bool {
	if !reKey.MatchString(key) {
		return false
	}
	if rest, ok := strings.CutPrefix(key, "tunnel."); ok {
		typ, ev, _ := strings.Cut(rest, ".")
		if !Contains(TunnelTypes, typ) {
			return false
		}
		if code, ok := strings.CutPrefix(ev, "failed."); ok {
			return Contains(FailureCodes, code)
		}
	}
	return true
}

// Contains reports whether list has v.
func Contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Snapshot is a copy of the counts now.
func (c *Counters) Snapshot() map[string]int {
	if c == nil {
		return map[string]int{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return maps.Clone(c.counts)
}

// Subtract takes away what a sent report carried, keeping what was counted
// since.
func (c *Counters) Subtract(sent map[string]int) {
	if c == nil {
		return
	}
	c.mu.Lock()
	for k, n := range sent {
		if c.counts[k] -= n; c.counts[k] <= 0 {
			delete(c.counts, k)
		}
	}
	c.dirty = true
	c.mu.Unlock()
}

// Flush writes the counts if they changed (0600, replaced atomically).
func (c *Counters) Flush() error {
	if c == nil || c.path == "" {
		return nil
	}
	c.mu.Lock()
	if !c.dirty {
		c.mu.Unlock()
		return nil
	}
	snap := maps.Clone(c.counts)
	c.dirty = false
	c.mu.Unlock()
	if err := writeCounts(c.path, snap); err != nil {
		c.mu.Lock()
		c.dirty = true
		c.mu.Unlock()
		return err
	}
	return nil
}

func writeCounts(path string, counts map[string]int) error {
	b, err := json.Marshal(struct {
		V      int            `json:"v"`
		Counts map[string]int `json:"counts"`
	}{1, counts})
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// AddToFile counts n more of key straight into dir's counters file: for
// what happens before the daemon has opened its Counters (the update boot
// guard), which can't know the telemetry level yet. The file is there only
// while telemetry is on (Keep), so with it off nothing is counted. The
// daemon loads the file after.
func AddToFile(dir, key string, n int) error {
	if !ValidKey(key) {
		return fmt.Errorf("telemetry: unknown counter %q", key)
	}
	path := countersFile(dir)
	if _, err := os.Stat(path); err != nil {
		return nil // telemetry off (or never on)
	}
	counts := readCounts(path)
	counts[key] = min(counts[key]+n, maxCount)
	return writeCounts(path, counts)
}

// Keep makes sure the counters file exists, so what AddToFile counts before
// the next start is kept (telemetry on).
func (c *Counters) Keep() error {
	if c == nil || c.path == "" {
		return nil
	}
	if _, err := os.Stat(c.path); err == nil {
		return nil
	}
	c.mu.Lock()
	c.dirty = true
	c.mu.Unlock()
	return c.Flush()
}

// Discard forgets every count and deletes the file (telemetry off).
func (c *Counters) Discard() {
	if c == nil || c.path == "" {
		return
	}
	c.mu.Lock()
	clear(c.counts)
	c.dirty = false
	c.mu.Unlock()
	_ = os.Remove(c.path)
}
