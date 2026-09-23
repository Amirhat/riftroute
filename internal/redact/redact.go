// Package redact scrubs identifying data out of text a user may post publicly
// (bug reports): IP and MAC addresses, domains, URLs, profile/list/app/user
// names, host and interface names, home-directory paths, and the timezone in
// timestamps (which alone can reveal a country). Each distinct value maps to a
// stable placeholder — <ip4-lan-1>, <domain-2>, <profile-1> — so the report
// keeps its structure ("default via <ip4-lan-1> dev en0" still reads as a
// route) without the value. It errs toward over-redacting: the user reviews
// the result before sharing it.
package redact

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Kind labels a known sensitive value; it becomes the placeholder's prefix.
type Kind string

const (
	Profile Kind = "profile"
	List    Kind = "list"
	Domain  Kind = "domain"
	App     Kind = "app"
	User    Kind = "user"
	Host    Kind = "host"
	Iface   Kind = "iface"
	URL     Kind = "url"
	Rule    Kind = "rule" // other rule values (ASN, country)
)

// Redactor replaces sensitive values with stable placeholders. Safe for
// concurrent use; one instance per report keeps placeholders consistent
// across its sections.
type Redactor struct {
	mu     sync.Mutex
	tokens []token
	sorted bool
	ph     map[string]string // kind+"\x00"+canonical value → placeholder
	n      map[string]int    // placeholder prefix → last number used
}

type token struct {
	value string
	kind  Kind
}

// New returns an empty Redactor (pattern rules only until Add is called).
func New() *Redactor {
	return &Redactor{ph: map[string]string{}, n: map[string]int{}}
}

// Add registers literal values to replace wherever they appear as a whole word
// (e.g. a profile name). One-character values are ignored — they identify
// nothing and would shred the text. Domains match case-insensitively and also
// cover their subdomains.
func (r *Redactor) Add(kind Kind, values ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range values {
		v = strings.TrimSpace(v)
		if kind == Domain {
			v = strings.Trim(strings.TrimPrefix(v, "*."), ".")
		}
		if caseless(kind) {
			v = asciiLower(v)
		}
		if utf8.RuneCountInString(v) < 2 {
			continue
		}
		r.tokens = append(r.tokens, token{value: v, kind: kind})
		r.sorted = false
	}
}

// Count reports how many distinct values have been replaced so far.
func (r *Redactor) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.ph)
}

// placeholder returns the stable placeholder for a value of a class.
// Caller holds r.mu.
func (r *Redactor) placeholder(class, canonical string) string {
	key := class + "\x00" + canonical
	if p, ok := r.ph[key]; ok {
		return p
	}
	r.n[class]++
	p := fmt.Sprintf("<%s-%d>", class, r.n[class])
	r.ph[key] = p
	return p
}

var (
	reURL       = regexp.MustCompile(`(?i)\b(?:https?|wss?|ftp)://[^\s"'<>]+`)
	reTimestamp = regexp.MustCompile(`\b(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2}(?:\.\d+)?)(Z|[+-]\d{2}:?\d{2})`)
	reMAC       = regexp.MustCompile(`(?i)\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b`)
	reIPv6      = regexp.MustCompile(`(?i)[0-9a-f]*:[0-9a-f]*:[0-9a-f.:]*(?:%[0-9a-z]+)?(?:/\d{1,3})?`)
	reIPv4      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b`)
	reHome      = regexp.MustCompile(`(/Users|/home)/[^/\s"'<>:]+`)
	reDomain    = regexp.MustCompile(`(?i)\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\b`)
)

// String returns s with every sensitive value replaced.
func (r *Redactor) String(s string) string {
	if s == "" {
		return s
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.sorted {
		// Longest first, so "corp.example.com" wins over "example.com".
		sort.SliceStable(r.tokens, func(i, j int) bool { return len(r.tokens[i].value) > len(r.tokens[j].value) })
		r.sorted = true
	}

	s = reURL.ReplaceAllStringFunc(s, func(u string) string { return r.placeholder(string(URL), u) })
	for _, t := range r.tokens {
		s = r.replaceToken(s, t)
	}
	s = reTimestamp.ReplaceAllStringFunc(s, toUTC)
	s = reMAC.ReplaceAllStringFunc(s, func(m string) string { return r.placeholder("mac", strings.ToLower(m)) })
	s = reIPv6.ReplaceAllStringFunc(s, r.ipv6)
	s = reIPv4.ReplaceAllStringFunc(s, r.ipv4)
	s = reHome.ReplaceAllString(s, "$1/<user>")
	s = reDomain.ReplaceAllStringFunc(s, r.domain)
	return s
}

// replaceToken swaps whole-word occurrences of one known value.
func (r *Redactor) replaceToken(s string, t token) string {
	hay := s
	if caseless(t.kind) {
		hay = asciiLower(s)
	}
	var b strings.Builder
	last := 0
	for i := 0; ; {
		j := strings.Index(hay[i:], t.value)
		if j < 0 {
			break
		}
		start, end := i+j, i+j+len(t.value)
		if !boundaryBefore(s, start) || !boundaryAfter(s, end) {
			i = start + 1
			continue
		}
		sub := start
		if t.kind == Domain && start > last && s[start-1] == '.' {
			// Hide subdomain labels too, keeping the apex relation visible:
			// "api.corp.example.com" → "<sub-1>.<domain-1>".
			for sub > last && isLabelOrDot(s[sub-1]) {
				sub--
			}
			if strings.Trim(s[sub:start], ".-") == "" {
				sub = start // just the dot of "*.": no labels to hide
			}
		}
		b.WriteString(s[last:sub])
		if sub < start {
			b.WriteString(r.placeholder("sub", asciiLower(strings.TrimSuffix(s[sub:start], "."))) + ".")
		}
		b.WriteString(r.placeholder(string(t.kind), asciiLower(t.value)))
		last, i = end, end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// caseless kinds match regardless of case (DNS and host names are
// case-insensitive; "Amirs-MacBook-Pro" and "amirs-macbook-pro.local" are one).
func caseless(k Kind) bool { return k == Domain || k == Host }

// asciiLower lowercases A–Z only, so byte offsets in the lowered copy line up
// with the original (strings.ToLower can change the length of some runes).
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isLabelOrDot(c byte) bool { return c == '.' || c == '-' || isAlnum(c) }

// A known value matches wherever it isn't glued to more letters or digits.
// Punctuation, "-", "_" and "." all count as boundaries: "amir" is redacted
// in "amir-mbp", "/Users/amir_old" and "-Users-amir-" — erring toward
// over-redaction, which only costs readability, never privacy.
func boundaryBefore(s string, i int) bool { return i == 0 || !isAlnum(s[i-1]) }

func boundaryAfter(s string, i int) bool { return i >= len(s) || !isAlnum(s[i]) }

// toUTC rewrites a timestamp in UTC so the local offset (a location hint)
// never appears.
func toUTC(m string) string {
	sub := reTimestamp.FindStringSubmatch(m)
	zone := sub[3]
	if zone != "Z" && !strings.Contains(zone, ":") {
		zone = zone[:3] + ":" + zone[3:]
	}
	t, err := time.Parse(time.RFC3339Nano, sub[1]+"T"+sub[2]+zone)
	if err != nil {
		return m
	}
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// Addresses kept verbatim: they identify no one and matter for debugging.
var publicResolvers = map[string]bool{
	"1.1.1.1": true, "1.0.0.1": true, "8.8.8.8": true, "8.8.4.4": true,
	"9.9.9.9": true, "149.112.112.112": true, "208.67.222.222": true, "208.67.220.220": true,
	"2606:4700:4700::1111": true, "2606:4700:4700::1001": true,
	"2001:4860:4860::8888": true, "2001:4860:4860::8844": true,
}

var (
	cgnat    = netip.MustParsePrefix("100.64.0.0/10")
	docNets4 = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	}
	docNet6 = netip.MustParsePrefix("2001:db8::/32")
)

func (r *Redactor) ipv4(m string) string {
	addrPart, suffix := m, ""
	if i := strings.IndexByte(m, '/'); i >= 0 {
		addrPart, suffix = m[:i], m[i:]
	}
	a, err := netip.ParseAddr(addrPart)
	if err != nil {
		return m
	}
	return r.addr(a, suffix, m)
}

func (r *Redactor) ipv6(m string) string {
	addrPart, suffix := m, ""
	if i := strings.IndexByte(m, '/'); i >= 0 {
		addrPart, suffix = m[:i], m[i:]
	}
	a, err := netip.ParseAddr(addrPart)
	if err != nil || !strings.Contains(addrPart, ":") {
		return m // times, MACs, "host:port" pairs — not an address
	}
	return r.addr(a, suffix, m)
}

func (r *Redactor) addr(a netip.Addr, suffix, orig string) string {
	a = a.WithZone("") // zones are interface names; the placeholder covers it
	u := a.Unmap()
	switch {
	case u.IsUnspecified(), u.IsLoopback(), u.IsMulticast(), publicResolvers[u.String()], isNetmask(u):
		return orig
	case u.Is4() && (u == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || inAny(u, docNets4)):
		return orig
	case u.Is6() && docNet6.Contains(u):
		return orig
	}
	class := "ip4"
	if u.Is6() {
		class = "ip6"
	}
	switch {
	case u.IsPrivate():
		class += "-lan"
	case u.IsLinkLocalUnicast():
		class += "-ll"
	case u.Is4() && cgnat.Contains(u):
		class += "-cgnat"
	}
	return r.placeholder(class, u.String()) + suffix
}

func inAny(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// isNetmask reports a contiguous IPv4 mask like 255.255.255.0 (not a host).
func isNetmask(a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	if v == 0 || b[0] != 255 {
		return false
	}
	inv := ^v
	return inv&(inv+1) == 0
}

// Tokens that look like domains but are file names, identifiers, or our own
// public endpoints — never personal.
var (
	safeNames = map[string]bool{
		"riftroute.app": true, "riftroute.tellnew.tech": true, "tellnew.tech": true,
		"github.com": true, "api.github.com": true, "cloudflare-ech.com": true,
		"launchd.plist": true, "resolv.conf": true, "pf.conf": true,
	}
	safeLastLabel = map[string]bool{
		"log": true, "go": true, "conf": true, "plist": true, "yaml": true, "yml": true, "json": true,
		"sock": true, "db": true, "txt": true, "sh": true, "md": true, "ts": true, "tsx": true, "js": true,
		"service": true, "token": true, "tmp": true, "new": true, "prev": true, "bak": true, "err": true,
		"pid": true, "lock": true, "wal": true, "shm": true, "toml": true, "dmg": true, "deb": true,
	}
	safePrefix = []string{"com.riftroute.", "com.apple.", "org.freedesktop."}
)

func (r *Redactor) domain(m string) string {
	lower := strings.ToLower(m)
	labels := strings.Split(lower, ".")
	last := labels[len(labels)-1]
	if len(last) < 2 || len(last) > 24 || strings.Trim(last, "abcdefghijklmnopqrstuvwxyz") != "" {
		return m // no alphabetic TLD: a version, an address, a decimal
	}
	if safeNames[lower] || safeLastLabel[last] {
		return m
	}
	for _, p := range safePrefix {
		if strings.HasPrefix(lower, p) {
			return m
		}
	}
	return r.placeholder(string(Domain), lower)
}
