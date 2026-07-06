//go:build darwin

package macos

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

// PF policy routing (route-to) on macOS — the Darwin analogue of Linux Model B.
// The abstract policy rules the engine emits are materialized into a dedicated PF
// anchor. Because PF is declarative (you replace an anchor's whole ruleset, not
// individual rules), each mutation is a read-modify-write of the anchor; the live
// anchor — enumerated via `pfctl -sr` and its ownership labels — is the source of
// truth (like Linux proto-tagged rules), so this survives daemon restarts and
// crash recovery without extra bookkeeping. Everything is exec-only, arg-array,
// and confined to our own anchor; teardown (FlushOwned / Panic) empties the
// anchor, removes the pf.conf reference, and releases our `pfctl -E` enable
// token, so nothing we added outlives us.

const (
	pfConfPath   = "/etc/pf.conf"
	pfConfBackup = "/etc/pf.conf.riftroute.bak"
	// pfTokenPath stores the reference token `pfctl -E` returns, so teardown can
	// release OUR enable reference (`pfctl -X <token>`) and leave PF exactly as we
	// found it. /var/run is root-owned and cleared at boot — matching the kernel's
	// own -E state, which also does not survive a reboot.
	pfTokenPath = "/var/run/riftroute.pf.token"
	pfctlTO     = 10 * time.Second
	// pfReadTTL caches anchor reads briefly: the drift computation enumerates
	// rules for both families on every state broadcast (every ~3s), which would
	// otherwise fork pfctl twice per broadcast forever.
	pfReadTTL = 2 * time.Second
)

// pfMu serializes anchor read-modify-write so concurrent Add/DelRule (and the
// hook edit of the shared pf.conf) can't clobber each other.
var pfMu sync.Mutex

// pfCache is the TTL cache of the parsed live anchor (guarded by pfMu).
var pfCache struct {
	rules []domain.PolicyRule
	at    time.Time
	valid bool
}

// ListRules returns the route-to rules RiftRoute owns in its anchor, parsed back
// from the labeled rule text. This is the "actual" side the Apply Protocol and
// the drift computation reconcile against (mirrors Linux's proto-tagged `ip rule`
// enumeration). Read errors degrade to "no rules" here — reads must not break
// state assembly on a host where PF was never touched — while MUTATIONS treat the
// same errors as fatal (see readAnchor callers below).
func (p *Provider) ListRules(ctx context.Context, family domain.Family) ([]domain.PolicyRule, error) {
	pfMu.Lock()
	defer pfMu.Unlock()
	all, err := p.cachedAnchorRules(ctx)
	if err != nil {
		return []domain.PolicyRule{}, nil
	}
	out := make([]domain.PolicyRule, 0, len(all))
	for _, r := range all {
		if r.Family == family {
			out = append(out, r)
		}
	}
	return out, nil
}

// AddRule adds one route-to rule to the anchor (idempotent). Read-modify-write of
// the whole anchor, since PF has no per-rule add. A failed READ aborts the op —
// proceeding on a bad read would rewrite the anchor from an empty base and
// silently drop every other owned rule.
func (p *Provider) AddRule(ctx context.Context, mr domain.ManagedRule) error {
	if strings.TrimSpace(mr.RouteToIface) == "" {
		return fmt.Errorf("macos: policy rule %q has no route-to interface", mr.Selector)
	}
	pfMu.Lock()
	defer pfMu.Unlock()
	cur, err := p.readAnchor(ctx)
	if err != nil {
		return fmt.Errorf("macos: cannot read pf anchor before add: %w", err)
	}
	key := pfRuleKey(mr.PolicyRule)
	for _, r := range cur {
		if pfRuleKey(r) == key {
			return nil // already present → idempotent
		}
	}
	return p.loadAnchor(ctx, append(cur, mr.PolicyRule))
}

// DelRule removes one route-to rule from the anchor (idempotent). Like AddRule,
// a failed read aborts rather than reporting a delete that never happened.
func (p *Provider) DelRule(ctx context.Context, mr domain.ManagedRule) error {
	pfMu.Lock()
	defer pfMu.Unlock()
	cur, err := p.readAnchor(ctx)
	if err != nil {
		return fmt.Errorf("macos: cannot read pf anchor before delete: %w", err)
	}
	key := pfRuleKey(mr.PolicyRule)
	kept := make([]domain.PolicyRule, 0, len(cur))
	for _, r := range cur {
		if pfRuleKey(r) != key {
			kept = append(kept, r)
		}
	}
	if len(kept) == len(cur) {
		return nil // already absent → idempotent
	}
	return p.loadAnchor(ctx, kept)
}

// FlushOwned empties our PF anchor, removes the pf.conf reference, and releases
// our PF enable token, restoring the host's packet filter to its pre-RiftRoute
// baseline. Powers Panic and clean uninstall; idempotent and safe from any state.
func (p *Provider) FlushOwned(ctx context.Context) error {
	pfMu.Lock()
	defer pfMu.Unlock()
	_, _ = runCombined(ctx, "pfctl", "-a", pfAnchorName, "-F", "rules") // empty our anchor
	pfInvalidate()
	err := p.dropHook(ctx) // and drop the pf.conf reference
	p.releaseEnableToken(ctx)
	return err
}

// --- internals (caller holds pfMu) ---

// pfInvalidate drops the read cache (call after any anchor mutation).
func pfInvalidate() { pfCache.valid = false }

// cachedAnchorRules returns the live anchor's owned rules through a short TTL
// cache, so back-to-back reads (both families of one drift pass; 3s broadcasts)
// cost one pfctl exec instead of many.
func (p *Provider) cachedAnchorRules(ctx context.Context) ([]domain.PolicyRule, error) {
	if pfCache.valid && time.Since(pfCache.at) < pfReadTTL {
		return pfCache.rules, nil
	}
	rules, err := p.readAnchor(ctx)
	if err != nil {
		return nil, err
	}
	pfCache.rules, pfCache.at, pfCache.valid = rules, time.Now(), true
	return rules, nil
}

// readAnchor enumerates the live anchor. An absent anchor (never created on this
// host) reads as empty; any other pfctl failure (permission, timeout, /dev/pf
// trouble) is a real error the mutation paths must not ignore.
func (p *Provider) readAnchor(ctx context.Context) ([]domain.PolicyRule, error) {
	out, err := runCombined(ctx, "pfctl", "-a", pfAnchorName, "-sr")
	if err != nil {
		if strings.Contains(out, "not found") { // anchor never created → empty
			return nil, nil
		}
		return nil, fmt.Errorf("pfctl -a %s -sr: %w: %s", pfAnchorName, err, strings.TrimSpace(out))
	}
	return parseAnchorRules(out), nil
}

// loadAnchor writes the desired rule set into our anchor. With rules present it
// ensures the pf.conf hook + PF are enabled; with none it tears the hook down so
// we leave no trace.
func (p *Provider) loadAnchor(ctx context.Context, rules []domain.PolicyRule) error {
	pfInvalidate()
	if len(rules) == 0 {
		_, _ = runCombined(ctx, "pfctl", "-a", pfAnchorName, "-F", "rules")
		err := p.dropHook(ctx)
		p.releaseEnableToken(ctx)
		return err
	}
	if err := p.ensureHook(ctx); err != nil {
		return err
	}
	if err := runStdin(ctx, RenderAnchor(rules), "pfctl", "-a", pfAnchorName, "-f", "-"); err != nil {
		return fmt.Errorf("macos: load pf anchor %s: %w", pfAnchorName, err)
	}
	p.ensureEnabled(ctx)
	return nil
}

// ensureEnabled turns PF on via `pfctl -E` (reference-counted) and records the
// returned token so teardown can release exactly OUR reference with `pfctl -X`.
// Idempotent per teardown cycle: once a token is stored, no further -E is issued.
func (p *Provider) ensureEnabled(ctx context.Context) {
	if _, err := os.Stat(pfTokenPath); err == nil {
		return // we already hold an enable reference
	}
	out, _ := runCombined(ctx, "pfctl", "-E")
	if m := reEnableToken.FindStringSubmatch(out); m != nil {
		_ = os.WriteFile(pfTokenPath, []byte(m[1]), 0o600)
	}
}

var reEnableToken = regexp.MustCompile(`(?i)token\s*:\s*(\d+)`)

// releaseEnableToken gives back the PF enable reference we took (best-effort).
func (p *Provider) releaseEnableToken(ctx context.Context) {
	tok, err := os.ReadFile(pfTokenPath)
	if err != nil {
		return // we never enabled PF (or already released)
	}
	if t := strings.TrimSpace(string(tok)); t != "" {
		_, _ = runCombined(ctx, "pfctl", "-X", t)
	}
	_ = os.Remove(pfTokenPath)
}

// ensureHook makes pf.conf reference our anchor so its rules are actually
// evaluated (an unreferenced anchor is inert). Idempotent: it backs up pf.conf
// once, appends a single marked block, and reloads the main ruleset. Only ever
// runs the first time an include/per-app rule is applied — a host that never uses
// macOS policy routing never has its pf.conf touched.
func (p *Provider) ensureHook(ctx context.Context) error {
	conf, err := os.ReadFile(pfConfPath)
	if err != nil {
		return fmt.Errorf("macos: read %s: %w", pfConfPath, err)
	}
	if pfHasHook(string(conf)) {
		return nil
	}
	if _, statErr := os.Stat(pfConfBackup); statErr != nil {
		_ = writeFileAtomic(pfConfBackup, conf, 0o600) // keep a restore point (best-effort)
	}
	if err := writeFileAtomic(pfConfPath, []byte(pfInsertHook(string(conf))), fileModeOf(pfConfPath, 0o644)); err != nil {
		return fmt.Errorf("macos: write %s: %w", pfConfPath, err)
	}
	if out, err := runCombined(ctx, "pfctl", "-f", pfConfPath); err != nil {
		return fmt.Errorf("macos: reload pf.conf: %w: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// dropHook removes our pf.conf reference and reloads the main ruleset, so a
// teardown leaves the packet filter exactly as we found it. Best-effort and
// idempotent (missing file / absent block are non-errors).
func (p *Provider) dropHook(ctx context.Context) error {
	conf, err := os.ReadFile(pfConfPath)
	if err != nil {
		return nil // nothing to restore
	}
	if !pfHasHook(string(conf)) {
		return nil
	}
	if err := writeFileAtomic(pfConfPath, []byte(pfRemoveHook(string(conf))), fileModeOf(pfConfPath, 0o644)); err != nil {
		return fmt.Errorf("macos: restore %s: %w", pfConfPath, err)
	}
	_, _ = runCombined(ctx, "pfctl", "-f", pfConfPath) // reload without our anchor reference
	return nil
}

// writeFileAtomic writes via a same-directory temp file + rename, so a crash or
// power loss mid-write can never leave the SYSTEM FIREWALL CONFIG truncated —
// the old pf.conf stays intact until the new one is fully durable.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// fileModeOf preserves the target's existing permissions (falling back for new
// files), so rewriting pf.conf never widens or narrows what the admin set.
func fileModeOf(path string, fallback os.FileMode) os.FileMode {
	if fi, err := os.Stat(path); err == nil {
		return fi.Mode().Perm()
	}
	return fallback
}

// runStdin execs name with args, feeding stdin (used for `pfctl -f -`).
func runStdin(ctx context.Context, stdin, name string, args ...string) error {
	cctx, cancel := context.WithTimeout(ctx, pfctlTO)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Stdin = bytes.NewReader([]byte(stdin))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}
