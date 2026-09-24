package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters (RFC 9106's second recommended profile, adapted to a
// single low-traffic admin login on a shared host).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16

	// MinPasswordLen is the shortest admin password passwd accepts.
	MinPasswordLen = 12
)

// ErrNoPassword means the admin password hasn't been set yet.
var ErrNoPassword = errors.New("admin password not set — run: riftroute-server passwd")

// HashPassword returns an argon2id hash in the PHC string format.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword checks pw against an encoded argon2id hash in constant time.
func VerifyPassword(encoded, pw string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	b64 := base64.RawStdEncoding
	salt, err1 := b64.DecodeString(parts[4])
	want, err2 := b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// passwordFile is where the admin hash lives inside the data directory.
func passwordFile(dataDir string) string { return filepath.Join(dataDir, "admin.hash") }

// SetPassword validates, hashes and atomically stores the admin password
// (0600: only the service account can read it), then signs out every session
// and forgets every known device — a new password is also the way to evict
// whoever might have had the old one.
func SetPassword(dataDir, pw string) error {
	if len([]rune(pw)) < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	h, err := HashPassword(pw)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dataDir, ".admin.hash-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(h + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), passwordFile(dataDir)); err != nil {
		return err
	}
	st, err := openStore(filepath.Join(dataDir, "server.db"))
	if err != nil {
		return fmt.Errorf("password saved, but signing out existing sessions failed: %w", err)
	}
	defer st.close()
	if err := st.revokeAll(); err != nil {
		return fmt.Errorf("password saved, but signing out existing sessions failed: %w", err)
	}
	return nil
}

func readPasswordHash(dataDir string) (string, error) {
	b, err := os.ReadFile(passwordFile(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNoPassword
	}
	return strings.TrimSpace(string(b)), err
}

// randomToken is 32 random bytes, URL-safe.
func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func equalTokens(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// limiter throttles logins, per client and globally. An attempt is counted
// when it starts, not when the slow hash has said no, so simultaneous
// requests can't all slip past the check; a successful sign-in refunds it.
// The global cap stops a spread-out guesser but would also lock the owner
// out, so a known device (one that has signed in before) is held to its own
// per-client limit only. Clients are kept only as keyed hashes, only in
// memory, and only for the window — never logged or stored.
type limiter struct {
	mu        sync.Mutex
	secret    []byte
	window    time.Duration
	perClient int
	global    int
	fails     map[string][]time.Time
	all       []time.Time
}

func newLimiter(window time.Duration, perClient, global int) *limiter {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	return &limiter{secret: secret, window: window, perClient: perClient, global: global, fails: map[string][]time.Time{}}
}

func (l *limiter) key(client string) string {
	m := hmac.New(sha256.New, l.secret)
	m.Write([]byte(client))
	return hex.EncodeToString(m.Sum(nil))
}

func prune(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && !ts[i].After(cutoff) {
		i++
	}
	return ts[i:]
}

// begin counts an attempt by client and reports whether it may go ahead.
// trusted (a known device) skips the global cap.
func (l *limiter) begin(client string, trusted bool, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-l.window)
	k := l.key(client)
	l.fails[k] = prune(l.fails[k], cutoff)
	l.all = prune(l.all, cutoff)
	if len(l.fails[k]) >= l.perClient || (!trusted && len(l.all) >= l.global) {
		if len(l.fails[k]) == 0 {
			delete(l.fails, k)
		}
		return false
	}
	l.fails[k] = append(l.fails[k], now)
	if !trusted {
		l.all = append(l.all, now)
	}
	return true
}

// refund takes back the attempt begin counted at `at` (the server was busy,
// or the password was right).
func (l *limiter) refund(client string, trusted bool, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := l.key(client)
	l.fails[k] = dropOne(l.fails[k], at)
	if len(l.fails[k]) == 0 {
		delete(l.fails, k)
	}
	if !trusted {
		l.all = dropOne(l.all, at)
	}
}

// succeeded forgives the client's earlier failures as well.
func (l *limiter) succeeded(client string, trusted bool, at time.Time) {
	l.refund(client, trusted, at)
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, l.key(client))
}

func dropOne(ts []time.Time, at time.Time) []time.Time {
	for i := len(ts) - 1; i >= 0; i-- {
		if ts[i].Equal(at) {
			return append(ts[:i:i], ts[i+1:]...)
		}
	}
	return ts
}

// sweep forgets every client whose window has passed (a client that never
// comes back would otherwise stay in the map for good).
func (l *limiter) sweep(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-l.window)
	for k, ts := range l.fails {
		if ts = prune(ts, cutoff); len(ts) == 0 {
			delete(l.fails, k)
		} else {
			l.fails[k] = ts
		}
	}
	l.all = prune(l.all, cutoff)
}

// clients is how many clients the limiter currently remembers (tests).
func (l *limiter) clients() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.fails)
}
