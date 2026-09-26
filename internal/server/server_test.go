package server

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amirhat/riftroute/internal/domain"
)

type testEnv struct {
	t    *testing.T
	srv  *Server
	h    http.Handler
	now  time.Time
	logs *bytes.Buffer
	dir  string
	ip   string // what Cloudflare reports as the client
}

func newEnv(t *testing.T, password string) *testEnv {
	t.Helper()
	return newEnvKeys(t, password, nil)
}

func newEnvKeys(t *testing.T, password string, keys map[string]ed25519.PublicKey) *testEnv {
	t.Helper()
	dir := t.TempDir()
	if password != "" {
		if err := SetPassword(dir, password); err != nil {
			t.Fatal(err)
		}
	}
	e := &testEnv{t: t, now: time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC), logs: &bytes.Buffer{}, dir: dir, ip: "203.0.113.77"}
	srv, err := New(Config{
		DataDir: dir, Build: domain.BuildInfo{Version: "0.3.0", Commit: "abcdef1234567"},
		Logger: slog.New(slog.NewTextHandler(e.logs, nil)), Now: func() time.Time { return e.now },
		DiskFree:    func(string) (uint64, error) { return 42 << 30, nil },
		TrustedKeys: keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	e.srv, e.h = srv, srv.Handler()
	return e
}

// do sends a request as Caddy would (from loopback, with Cloudflare's header).
func (e *testEnv) do(method, target string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, target, body)
	r.RemoteAddr = "127.0.0.1:50000"
	r.Header.Set("CF-Connecting-IP", e.ip)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func cookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

var reCSRF = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// loginForm fetches the login page, returning its CSRF cookie and field.
func (e *testEnv) loginForm() (*http.Cookie, string) {
	w := e.do("GET", "/login", nil)
	m := reCSRF.FindStringSubmatch(w.Body.String())
	c := cookie(w, loginCSRF)
	if m == nil || c == nil {
		e.t.Fatalf("login form without CSRF: %s", w.Body.String())
	}
	return c, m[1]
}

func (e *testEnv) login(pw string, extra ...*http.Cookie) *httptest.ResponseRecorder {
	c, token := e.loginForm()
	return e.do("POST", "/login", url.Values{"csrf": {token}, "password": {pw}}, append([]*http.Cookie{c}, extra...)...)
}

func TestLandingPagesInBothLanguages(t *testing.T) {
	e := newEnv(t, "")
	for path, want := range map[string][]string{
		"/":   {`lang="en" dir="ltr"`, "Split tunneling you can trust.", `href="/fa"`, "sends nothing today", "releases/latest"},
		"/fa": {`lang="fa" dir="rtl"`, "تقسیم ترافیکی", `href="/"`, "هیچ داده‌ای نمی‌فرستد", "releases/latest"},
	} {
		w := e.do("GET", path, nil)
		if w.Code != 200 {
			t.Fatalf("%s: status %d", path, w.Code)
		}
		for _, s := range want {
			if !strings.Contains(w.Body.String(), s) {
				t.Errorf("%s lacks %q", path, s)
			}
		}
		if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
			t.Errorf("%s: Cache-Control %q (HTML must revalidate so new asset hashes are picked up)", path, cc)
		}
	}
}

func TestSecurityHeadersEverywhere(t *testing.T) {
	e := newEnv(t, "")
	for _, p := range []string{"/", "/fa", "/login", "/healthz", "/nope"} {
		h := e.do("GET", p, nil).Header()
		csp := h.Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("%s: CSP %q", p, csp)
		}
		for k, v := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
			if h.Get(k) != v {
				t.Errorf("%s: %s = %q", p, k, h.Get(k))
			}
		}
	}
}

// Assets live under a content hash and are immutable; a stale hash 404s
// rather than serving new bytes under an old, forever-cached URL.
func TestStaticAssetsAreHashedAndImmutable(t *testing.T) {
	e := newEnv(t, "")
	page := e.do("GET", "/", nil).Body.String()
	m := regexp.MustCompile(`href="(/static/[0-9a-f]{12}/site\.css)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no hashed stylesheet link in page")
	}
	w := e.do("GET", m[1], nil)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("asset: %d %q %q", w.Code, w.Header().Get("Cache-Control"), w.Header().Get("Content-Type"))
	}
	if w := e.do("GET", "/static/000000000000/site.css", nil); w.Code != 404 {
		t.Fatalf("stale hash: %d, want 404", w.Code)
	}
	// Self-hosted fonts: a fixed type (not the host's mime database) and a
	// CSP that allows them.
	font := strings.Replace(m[1], "site.css", "go-bold.ttf", 1)
	if w := e.do("GET", font, nil); w.Code != 200 || w.Header().Get("Content-Type") != "font/ttf" {
		t.Fatalf("font: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	if csp := e.do("GET", "/", nil).Header().Get("Content-Security-Policy"); !strings.Contains(csp, "font-src 'self'") {
		t.Fatalf("CSP doesn't allow our fonts: %q", csp)
	}
	// The Persian face ships with its licence, and only the Persian page
	// preloads it.
	if w := e.do("GET", strings.Replace(m[1], "site.css", "vazirmatn-nl-bold.woff2", 1), nil); w.Code != 200 || w.Header().Get("Content-Type") != "font/woff2" {
		t.Fatalf("vazirmatn: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	if w := e.do("GET", "/licenses/vazirmatn-ofl.txt", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "SIL Open Font License") {
		t.Fatalf("font licence: %d", w.Code)
	}
	if w := e.do("GET", "/licenses/../server.go", nil); w.Code == 200 {
		t.Fatal("licence route serves arbitrary files")
	}
	if strings.Contains(page, "vazirmatn") || !strings.Contains(e.do("GET", "/fa", nil).Body.String(), "vazirmatn-nl-bold.woff2") {
		t.Fatal("only the Persian page should preload Vazirmatn")
	}
}

func TestHealthz(t *testing.T) {
	e := newEnv(t, "")
	w := e.do("GET", "/healthz", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"version":"0.3.0"`) || !strings.Contains(w.Body.String(), `"commit":"abcdef1"`) {
		t.Fatalf("healthz: %d %s", w.Code, w.Body.String())
	}
}

func TestAdminRequiresLogin(t *testing.T) {
	e := newEnv(t, "correct horse battery")
	w := e.do("GET", "/admin", nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("anonymous /admin: %d → %q", w.Code, w.Header().Get("Location"))
	}
}

func TestLoginFlowAndSessionCookie(t *testing.T) {
	e := newEnv(t, "correct horse battery")
	w := e.login("correct horse battery")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin" {
		t.Fatalf("login: %d → %q\n%s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	sess := cookie(w, sessionCookie)
	if sess == nil || !sess.Secure || !sess.HttpOnly || sess.SameSite != http.SameSiteStrictMode || sess.Path != "/" || sess.Domain != "" {
		t.Fatalf("session cookie not locked down: %+v", sess)
	}
	a := e.do("GET", "/admin", nil, sess)
	body := a.Body.String()
	if a.Code != 200 || !strings.Contains(body, "0.3.0 (abcdef1)") || !strings.Contains(body, "42.0 GB") || a.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("admin: %d %q\n%s", a.Code, a.Header().Get("Cache-Control"), body)
	}

	// Logout needs the session's CSRF token.
	if w := e.do("POST", "/logout", url.Values{"csrf": {"forged"}}, sess); e.do("GET", "/admin", nil, sess).Code != 200 {
		t.Fatalf("a forged logout ended the session (%d)", w.Code)
	}
	token := reCSRF.FindStringSubmatch(body)[1]
	e.do("POST", "/logout", url.Values{"csrf": {token}}, sess)
	if w := e.do("GET", "/admin", nil, sess); w.Code != http.StatusSeeOther {
		t.Fatalf("session still valid after logout: %d", w.Code)
	}
}

func TestLoginRejectsMissingCSRFAndWrongPassword(t *testing.T) {
	e := newEnv(t, "correct horse battery")
	if w := e.do("POST", "/login", url.Values{"password": {"correct horse battery"}}); w.Code != http.StatusForbidden || cookie(w, sessionCookie) != nil {
		t.Fatalf("login without CSRF: %d", w.Code)
	}
	if w := e.login("wrong password!!"); w.Code != http.StatusUnauthorized || cookie(w, sessionCookie) != nil {
		t.Fatalf("wrong password: %d", w.Code)
	}
}

// Five failures per client, then 429 — and the client's address never
// reaches the log.
func TestLoginThrottleAndNoAddressesInLogs(t *testing.T) {
	e := newEnv(t, "correct horse battery")
	for i := 0; i < 5; i++ {
		if w := e.login("nope nope nope"); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i+1, w.Code)
		}
	}
	if w := e.login("correct horse battery"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt: %d, want 429 even with the right password", w.Code)
	}
	e.now = e.now.Add(16 * time.Minute)
	if w := e.login("correct horse battery"); w.Code != http.StatusSeeOther {
		t.Fatalf("after the window: %d", w.Code)
	}
	if strings.Contains(e.logs.String(), "203.0.113.77") {
		t.Fatalf("client address leaked into logs:\n%s", e.logs.String())
	}
}

func TestSessionsExpire(t *testing.T) {
	e := newEnv(t, "correct horse battery")
	sess := cookie(e.login("correct horse battery"), sessionCookie)
	e.now = e.now.Add(sessionTTL + time.Minute)
	if w := e.do("GET", "/admin", nil, sess); w.Code != http.StatusSeeOther {
		t.Fatalf("expired session still valid: %d", w.Code)
	}
}

func TestNoPasswordMeansNoLogin(t *testing.T) {
	e := newEnv(t, "")
	if !strings.Contains(e.do("GET", "/login", nil).Body.String(), "isn't set up yet") {
		t.Fatal("login page must say the admin password isn't set")
	}
	if w := e.login("anything at all!"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("login without a password file: %d", w.Code)
	}
}

func TestPasswordHashing(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil || !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("hash %q err %v", h, err)
	}
	if !VerifyPassword(h, "correct horse battery") || VerifyPassword(h, "correct horse batterY") || VerifyPassword("garbage", "x") {
		t.Fatal("verify is wrong")
	}
	if err := SetPassword(t.TempDir(), "short"); err == nil {
		t.Fatal("short password accepted")
	}
}

func TestOversizedFormRejected(t *testing.T) {
	e := newEnv(t, "correct horse battery")
	c, token := e.loginForm()
	w := e.do("POST", "/login", url.Values{"csrf": {token}, "password": {strings.Repeat("x", 8<<10)}}, c)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized form: %d", w.Code)
	}
}

// Simultaneous attempts are counted when they start, not after the slow hash:
// a burst from one client gets at most five password checks, never sixteen.
func TestSimultaneousLoginsCountedUpFront(t *testing.T) {
	e := newEnv(t, "correct horse battery")
	c, token := e.loginForm()
	var wg sync.WaitGroup
	codes := make(chan int, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- e.do("POST", "/login", url.Values{"csrf": {token}, "password": {"nope nope nope"}}, c).Code
		}()
	}
	wg.Wait()
	close(codes)
	checked := 0
	for code := range codes {
		switch code {
		case http.StatusUnauthorized:
			checked++
		case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		default:
			t.Errorf("unexpected status %d", code)
		}
	}
	if checked > 5 {
		t.Fatalf("%d password checks for one client in one burst, want at most 5", checked)
	}
}

// Password checks run one at a time; a request that can't get a turn is told
// the server is busy and gets its attempt back.
func TestBusyPasswordCheckRefundsTheAttempt(t *testing.T) {
	old := verifyWait
	verifyWait = 20 * time.Millisecond
	t.Cleanup(func() { verifyWait = old })
	e := newEnv(t, "correct horse battery")
	e.srv.verify <- struct{}{} // another check is running
	for i := 0; i < 6; i++ {
		if w := e.login("nope nope nope"); w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "busy") {
			t.Fatalf("while busy: %d", w.Code)
		}
	}
	<-e.srv.verify
	if w := e.login("correct horse battery"); w.Code != http.StatusSeeOther {
		t.Fatalf("after busy answers: %d, want sign-in (busy answers must not count)", w.Code)
	}
}

// A flood from many addresses fills the global cap; the owner's browser,
// which has signed in before, still gets in.
func TestKnownDeviceIsNotLockedOutByTheGlobalCap(t *testing.T) {
	e := newEnv(t, "correct horse battery")
	first := e.login("correct horse battery")
	dev := cookie(first, deviceCookie)
	if dev == nil || !dev.Secure || !dev.HttpOnly || dev.SameSite != http.SameSiteStrictMode || dev.Path != "/" {
		t.Fatalf("device cookie not issued or not locked down: %+v", dev)
	}
	for i := 0; i < 50; i++ {
		e.srv.lim.begin(fmt.Sprintf("198.51.100.%d", i), false, e.now)
	}
	e.ip = "192.0.2.10"
	if w := e.login("correct horse battery"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("unknown browser under a flood: %d, want 429", w.Code)
	}
	if w := e.login("correct horse battery", dev); w.Code != http.StatusSeeOther {
		t.Fatalf("known device under a flood: %d, want sign-in", w.Code)
	}
	// ...but a known device still has its own limit.
	for i := 0; i < 5; i++ {
		e.login("nope nope nope", dev)
	}
	if w := e.login("correct horse battery", dev); w.Code != http.StatusTooManyRequests {
		t.Fatalf("known device after 5 failures: %d, want 429", w.Code)
	}
}

func TestIPv6ClientsCountPerSlash64(t *testing.T) {
	key := func(ip string) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("CF-Connecting-IP", ip)
		return clientKey(r)
	}
	if a, b := key("2001:db8:1:2::1"), key("2001:db8:1:2:ffff:eeee:dddd:cccc"); a != b {
		t.Errorf("same /64, different keys: %q %q", a, b)
	}
	if a, b := key("2001:db8:1:2::1"), key("2001:db8:1:3::1"); a == b {
		t.Errorf("different /64s share a key: %q", a)
	}
	if k := key("203.0.113.9"); k != "203.0.113.9" {
		t.Errorf("IPv4 key %q", k)
	}
}

// A new password signs out every session and forgets every device.
func TestNewPasswordSignsEveryoneOut(t *testing.T) {
	e := newEnv(t, "correct horse battery")
	w := e.login("correct horse battery")
	sess, dev := cookie(w, sessionCookie), cookie(w, deviceCookie)
	if err := SetPassword(e.dir, "a different passphrase"); err != nil {
		t.Fatal(err)
	}
	if w := e.do("GET", "/admin", nil, sess); w.Code != http.StatusSeeOther {
		t.Fatalf("old session survived the password change: %d", w.Code)
	}
	if _, known := e.srv.knownDevice(httptest.NewRequest("GET", "/", nil)); known {
		t.Fatal("request without a device cookie counted as known")
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(dev)
	if _, known := e.srv.knownDevice(r); known {
		t.Fatal("device survived the password change")
	}
}

// Redirects (and everything else a handler doesn't mark cacheable) are
// no-store: a cached /admin → /login could loop a signed-in admin.
func TestRedirectsAreNeverCached(t *testing.T) {
	e := newEnv(t, "correct horse battery")
	sess := cookie(e.login("correct horse battery"), sessionCookie)
	for name, w := range map[string]*httptest.ResponseRecorder{
		"anonymous /admin": e.do("GET", "/admin", nil),
		"signed-in /login": e.do("GET", "/login", nil, sess),
		"404":              e.do("GET", "/nope", nil),
	} {
		if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s: Cache-Control %q", name, cc)
		}
	}
}

func TestThrottleForgetsIdleClients(t *testing.T) {
	e := newEnv(t, "")
	for i := 0; i < 10; i++ {
		e.srv.lim.begin(fmt.Sprintf("198.51.100.%d", i), false, e.now)
	}
	e.now = e.now.Add(16 * time.Minute)
	e.srv.maintain()
	if n := e.srv.lim.clients(); n != 0 {
		t.Fatalf("throttle still remembers %d idle clients", n)
	}
}
