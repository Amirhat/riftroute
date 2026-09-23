// Package redact scrubs identifying data out of text a user may post publicly
// (bug reports): IP and MAC addresses, e-mail addresses, domains, URLs,
// profile/list/app/user names, host and interface names, home-directory
// paths, and the timezone in timestamps (which alone can reveal a country).
// Each distinct value maps to a stable placeholder — <ip4-lan-1>, <domain-2>,
// <profile-1> — so the report keeps its structure ("default via <ip4-lan-1>
// dev en0" still reads as a route) without the value. It errs toward
// over-redacting: the user reviews the result before sharing it.
//
// Two layers: values the caller KNOWS (Add) are replaced wherever they occur,
// in any escaping the logger may have applied; and names nobody registered —
// a deleted profile in an old log line, a report built while the daemon is
// down — are caught by where they sit (`profile "…"`, `list=…`, `iface=…`).
package redact

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
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
	ph     map[string]string // class+"\x00"+canonical value → placeholder
	n      map[string]int    // placeholder class → last number used
}

// token is one spelling of a known value; canon is the value itself, so every
// spelling (raw, %q-escaped, escaped twice) maps to the same placeholder.
type token struct {
	value string
	canon string
	kind  Kind
}

// New returns an empty Redactor (pattern rules only until Add is called).
func New() *Redactor {
	return &Redactor{ph: map[string]string{}, n: map[string]int{}}
}

// Add registers literal values to replace wherever they appear, not glued to
// other letters or digits. One-character values are ignored — they identify
// nothing and would shred the text. Domains and host names match
// case-insensitively; domains also cover their subdomains.
//
// Each value is also registered as Go's %q / slog would print it, once and
// twice escaped (an error quoting a name, logged as a quoted attribute):
// `Mom's "Bank"` appears in logs as `Mom's \"Bank\"`, and a Persian name's
// zero-width non-joiner (U+200C) as a \u escape.
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
		q1 := unquoted(strconv.Quote(v))
		q2 := unquoted(strconv.Quote(q1))
		seen := map[string]bool{}
		for _, spelling := range []string{v, q1, q2} {
			if !seen[spelling] {
				seen[spelling] = true
				r.tokens = append(r.tokens, token{value: spelling, canon: v, kind: kind})
			}
		}
		r.sorted = false
	}
}

func unquoted(q string) string { return q[1 : len(q)-1] }

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
	reURL       = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]{1,15}://[^\s"'<>]+`)
	reEmail     = regexp.MustCompile(`(?i)[a-z0-9._%+-]+@[\p{L}\p{N}.-]+\.[\p{L}]{2,}`)
	reTimestamp = regexp.MustCompile(`\b(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2}(?:\.\d+)?)(Z|[+-]\d{2}:?\d{2})`)
	reKeyword   = regexp.MustCompile(`(?i)\b(profile|list|rule|iface|interface)(=|:?[ \t]+)`)
	reIPv6      = regexp.MustCompile(`(?i)[0-9a-f]*:[0-9a-f]*:[0-9a-f.:]*(?:%[0-9a-z]+)?(?:/\d{1,3})?`)
	reMAC       = regexp.MustCompile(`(?i)\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b`)
	reIPv4      = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?`)
	reIPv4Short = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){1,2}/\d{1,2}\b`) // macOS netstat: 10.8/16, 192.168.88/24
	reHome      = regexp.MustCompile(`(\\?/(?:Users|home)\\?/)[^/\\\s"'<>:]+`)
	reDomain    = regexp.MustCompile(`[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?(?:\.[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?)+`)
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
	s = reEmail.ReplaceAllStringFunc(s, func(e string) string { return r.placeholder("email", strings.ToLower(e)) })
	for _, t := range r.tokens {
		s = r.replaceToken(s, t)
	}
	s = r.keywordValues(s)
	s = reTimestamp.ReplaceAllStringFunc(s, toUTC)
	s = reIPv6.ReplaceAllStringFunc(s, r.ipv6) // before MACs: a MAC-shaped run inside an IPv6 address is the address
	s = reMAC.ReplaceAllStringFunc(s, func(m string) string { return r.placeholder("mac", strings.ToLower(m)) })
	s = r.ipv4All(s)
	s = reIPv4Short.ReplaceAllStringFunc(s, r.ipv4Short)
	s = reHome.ReplaceAllString(s, "$1<user>")
	s = r.domains(s)
	return s
}

// replaceToken swaps occurrences of one spelling of a known value.
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
		b.WriteString(r.placeholder(string(t.kind), asciiLower(t.canon)))
		last, i = end, end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// keywordValues masks names by position, for names nobody registered: a
// quoted value after profile/list/rule (`profile "Old Bank"`, and the same
// inside an escaped log attribute, `profile \"Old Bank\"`), an unquoted
// `profile=`/`list=` attribute, and a non-generic `iface=` name.
func (r *Redactor) keywordValues(s string) string {
	var b strings.Builder
	last := 0
	for _, m := range reKeyword.FindAllStringSubmatchIndex(s, -1) {
		kw := strings.ToLower(s[m[2]:m[3]])
		isEq := s[m[4]:m[5]] == "="
		vs := m[1]
		if vs < last || vs >= len(s) {
			continue
		}
		ve, content, quoted := scanValue(s, vs)
		if ve <= vs || strings.HasPrefix(content, "<") && strings.HasSuffix(content, ">") {
			continue // nothing there, or already a placeholder
		}
		class := kw
		switch kw {
		case "iface", "interface":
			if !isEq || quoted || GenericIface(content) {
				continue
			}
			class = string(Iface)
		case "rule":
			if !quoted {
				continue // `rule=*.<domain-1>` keeps its useful shape
			}
		default: // profile, list
			if !quoted && !isEq {
				continue // prose: "the profile set is…"
			}
		}
		b.WriteString(s[last:vs])
		ph := r.placeholder(class, asciiLower(unescape(content)))
		if quoted {
			open := s[vs : strings.IndexByte(s[vs:], '"')+vs+1]
			b.WriteString(open + ph + open)
		} else {
			b.WriteString(ph)
		}
		last = ve
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// scanValue reads the value starting at i: either a quoted string opened by
// k backslashes and a quote (closed by a quote preceded by exactly k
// backslashes — deeper escapes belong to the content), or a bare word.
func scanValue(s string, i int) (end int, content string, quoted bool) {
	k := 0
	for i+k < len(s) && s[i+k] == '\\' {
		k++
	}
	if i+k < len(s) && s[i+k] == '"' {
		body := i + k + 1
		for j := body; j < len(s); j++ {
			if s[j] != '"' {
				continue
			}
			run := 0
			for p := j - 1; p >= body && s[p] == '\\'; p-- {
				run++
			}
			if run == k {
				return j + 1, s[body : j-k], true
			}
		}
		return i, "", false // unterminated: leave it
	}
	j := i
	for j < len(s) && !strings.ContainsRune(" \t\n\r\"',;()[]{}\\", rune(s[j])) {
		j++
	}
	return j, s[i:j], false
}

// unescape undoes up to two levels of Go quoting so every spelling of a name
// shares one placeholder.
func unescape(v string) string {
	for n := 0; n < 3 && strings.ContainsRune(v, '\\'); n++ {
		u, err := strconv.Unquote(`"` + v + `"`)
		if err != nil {
			break
		}
		v = u
	}
	return v
}

var genericIface = regexp.MustCompile(`^(lo|en|eth|wlan|wlp|wwan|enp|eno|ens|utun|ipsec|ppp|tun|tap|wg|bridge|br|awdl|llw|anpi|ap|gif|stf|docker|veth|virbr|vmnet|vboxnet|p2p|pktap)\d*([a-z]\d+)*$`)

// GenericIface reports whether an interface name is a generic OS/driver name
// (en0, utun4, wlp2s0) rather than one that names a product or provider
// (nordlynx, wg-mullvad, ham0, zt3jnkd3).
func GenericIface(name string) bool { return genericIface.MatchString(name) }

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

// ipv4All replaces dotted quads not glued to more digits or dots — so
// "gw_192.168.1.1" and "10.0.0.1_ext" are caught while "1.2.3.4.5" (not an
// address) is left alone.
func (r *Redactor) ipv4All(s string) string {
	var b strings.Builder
	last := 0
	for _, m := range reIPv4.FindAllStringIndex(s, -1) {
		start, end := m[0], m[1]
		if start > 0 && (isDigit(s[start-1]) || s[start-1] == '.') {
			continue
		}
		if end < len(s) && (isDigit(s[end]) || s[end] == '.' && end+1 < len(s) && isDigit(s[end+1])) {
			continue
		}
		b.WriteString(s[last:start])
		b.WriteString(r.ipv4(s[start:end]))
		last = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func (r *Redactor) ipv4(m string) string {
	addrPart, suffix := m, ""
	if i := strings.IndexByte(m, '/'); i >= 0 {
		addrPart, suffix = m[:i], m[i:]
	}
	a, err := netip.ParseAddr(addrPart)
	if err != nil {
		// Zero-padded octets ("192.168.001.001") are still an address.
		parts := strings.Split(addrPart, ".")
		for i, p := range parts {
			if t := strings.TrimLeft(p, "0"); t != "" {
				parts[i] = t
			} else {
				parts[i] = "0"
			}
		}
		if a, err = netip.ParseAddr(strings.Join(parts, ".")); err != nil {
			return m
		}
	}
	return r.addr(a, suffix, m)
}

// ipv4Short handles netstat's abbreviated networks (10.8/16 = 10.8.0.0/16).
func (r *Redactor) ipv4Short(m string) string {
	slash := strings.IndexByte(m, '/')
	parts := strings.Split(m[:slash], ".")
	for len(parts) < 4 {
		parts = append(parts, "0")
	}
	a, err := netip.ParseAddr(strings.Join(parts, "."))
	if err != nil {
		return m
	}
	return r.addr(a, m[slash:], m)
}

// ipv6 redacts one candidate run of hex digits and colons. The run can drag
// in neighbouring punctuation — "2a01:4f8::1:" (route's error format),
// "dst:2a01:…", netstat's "2a01:4f8::2.443" — so when it doesn't parse, the
// ends are peeled and the address retried, keeping what was peeled.
func (r *Redactor) ipv6(m string) string {
	type cut struct{ pre, addr, post string }
	cands := []cut{{"", m, ""}}
	if strings.HasPrefix(m, ":") && !strings.HasPrefix(m, "::") {
		cands = append(cands, cut{":", m[1:], ""})
	}
	for _, c := range append([]cut(nil), cands...) {
		if t := strings.TrimRight(c.addr, ".:"); t != c.addr && !strings.HasSuffix(c.addr, "::") {
			cands = append(cands, cut{c.pre, t, c.addr[len(t):]})
		}
		if i := strings.LastIndexByte(c.addr, '.'); i > 0 {
			cands = append(cands, cut{c.pre, c.addr[:i], c.addr[i:]})
		}
	}
	for _, c := range cands {
		addrPart, suffix := c.addr, ""
		if i := strings.IndexByte(addrPart, '/'); i >= 0 {
			addrPart, suffix = addrPart[:i], addrPart[i:]
		}
		if !strings.Contains(addrPart, ":") {
			continue
		}
		if a, err := netip.ParseAddr(addrPart); err == nil {
			return c.pre + r.addr(a, suffix, c.addr) + c.post
		}
	}
	return m // times, MACs, "host:port" pairs — not an address
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
// public endpoints — never personal. Real TLDs (.md, .sh, .new, .app) are not
// treated as file extensions: those names are redacted unless listed here.
var (
	safeNames = map[string]bool{
		"riftroute.app": true, "riftroute.tellnew.tech": true, "tellnew.tech": true,
		"github.com": true, "api.github.com": true, "cloudflare-ech.com": true,
		"launchd.plist": true, "resolv.conf": true, "pf.conf": true,
	}
	safeLastLabel = map[string]bool{
		"log": true, "go": true, "conf": true, "plist": true, "yaml": true, "yml": true, "json": true,
		"sock": true, "db": true, "txt": true, "ts": true, "tsx": true, "js": true,
		"service": true, "token": true, "tmp": true, "prev": true, "bak": true, "err": true,
		"pid": true, "lock": true, "wal": true, "shm": true, "toml": true, "dmg": true, "deb": true,
	}
	safePrefix = []string{"com.riftroute.", "com.apple.", "org.freedesktop.", "riftrouted.", "riftroute."}
)

// domains replaces domain-shaped names (Unicode and punycode included). A
// path straight after a redacted domain ("lists.example.net/iran.txt?token=…",
// a URL without its scheme) goes with it.
func (r *Redactor) domains(s string) string {
	var b strings.Builder
	last := 0
	for _, m := range reDomain.FindAllStringIndex(s, -1) {
		start, end := m[0], m[1]
		if start < last {
			continue
		}
		name := s[start:end]
		if !r.sensitiveDomain(name) {
			continue
		}
		b.WriteString(s[last:start])
		b.WriteString(r.placeholder(string(Domain), strings.ToLower(name)))
		if end < len(s) && s[end] == '/' {
			for end < len(s) && !strings.ContainsRune(" \t\n\r\"'<>", rune(s[end])) {
				end++
			}
			b.WriteString("/…")
		}
		last = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func (r *Redactor) sensitiveDomain(name string) bool {
	lower := strings.ToLower(name)
	labels := strings.Split(lower, ".")
	if !isTLD(labels[len(labels)-1]) {
		return false // a version, an address, a decimal
	}
	if safeNames[lower] || safeLastLabel[labels[len(labels)-1]] {
		return false
	}
	for _, p := range safePrefix {
		if strings.HasPrefix(lower, p) {
			return false
		}
	}
	return true
}

// isTLD: letters only (any script), 2–24 of them, or an IDN in punycode.
func isTLD(l string) bool {
	if strings.HasPrefix(l, "xn--") && len(l) > 4 {
		return true
	}
	n := 0
	for _, c := range l {
		if !unicode.IsLetter(c) {
			return false
		}
		n++
	}
	return n >= 2 && n <= 24
}
