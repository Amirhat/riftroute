// Package server is riftroute-server: the public site at riftroute.tellnew.tech
// (bilingual landing page) and the admin dashboard behind a password. It
// listens on loopback only, behind Caddy/Cloudflare, keeps no access log, and
// never records client addresses (the login throttle holds keyed hashes in
// memory for its window only). Later phases add the update API, telemetry
// ingest and bug-report upload here.
package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/Amirhat/riftroute/internal/buildinfo"
	"github.com/Amirhat/riftroute/internal/domain"
)

// Explicit extensions: a stray file in the folder (.DS_Store, an editor's
// backup) must never ship, let alone under a year-long public cache header.
//
//go:embed web/templates/*.html web/static/*.css web/static/*.svg web/static/*.png web/static/*.ttf
var webFS embed.FS

const (
	sessionCookie = "__Host-rr_session"
	loginCSRF     = "__Host-rr_login"
	deviceCookie  = "__Host-rr_device"
	sessionTTL    = 12 * time.Hour
	deviceTTL     = 180 * 24 * time.Hour
	maxFormBytes  = 4 << 10
)

// verifyWait is how long a login waits for the password check to be free
// before answering "busy" (checks run one at a time: each takes 64 MiB, and
// the host is shared). A variable for tests.
var verifyWait = 3 * time.Second

// Config configures a Server.
type Config struct {
	DataDir string
	Build   domain.BuildInfo
	Logger  *slog.Logger
	Now     func() time.Time // tests
	// DiskFree reports free bytes on the data volume (nil: not shown).
	DiskFree func(path string) (uint64, error)
}

// Server serves the site and the admin area.
type Server struct {
	cfg       Config
	st        *store
	lim       *limiter
	verify    chan struct{} // one password check at a time
	tmpl      *template.Template
	static    map[string][]byte
	assetHash string
	started   time.Time
	mux       *http.ServeMux
}

// New opens the data directory's database and prepares the handlers.
func New(cfg Config) (*Server, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	st, err := openStore(path.Join(cfg.DataDir, "server.db"))
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	s := &Server{cfg: cfg, st: st, lim: newLimiter(15*time.Minute, 5, 50), verify: make(chan struct{}, 1), started: cfg.Now(), static: map[string][]byte{}}
	if err := s.loadStatic(); err != nil {
		return nil, err
	}
	s.tmpl, err = template.New("").Funcs(template.FuncMap{
		"asset": func(name string) string { return "/static/" + s.assetHash + "/" + name },
		"bytes": humanBytes,
	}).ParseFS(webFS, "web/templates/*.html")
	if err != nil {
		return nil, err
	}
	s.routes()
	if _, err := readPasswordHash(cfg.DataDir); errors.Is(err, ErrNoPassword) {
		cfg.Logger.Warn("admin login disabled until a password is set", "hint", "riftroute-server passwd")
	} else if err != nil {
		cfg.Logger.Error("admin login disabled: can't read the password file", "err", err)
	}
	return s, nil
}

// Close releases the database.
func (s *Server) Close() error { return s.st.close() }

// Maintain prunes expired sessions, stale devices and the login throttle's
// memory until ctx ends.
func (s *Server) Maintain(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.maintain()
		}
	}
}

func (s *Server) maintain() {
	now := s.cfg.Now()
	if err := s.st.pruneSessions(now); err != nil {
		s.cfg.Logger.Warn("session prune failed", "err", err)
	}
	if err := s.st.pruneDevices(now); err != nil {
		s.cfg.Logger.Warn("device prune failed", "err", err)
	}
	s.lim.sweep(now)
}

// loadStatic reads the embedded assets and derives the cache-busting hash:
// assets are served under /static/<hash>/ as immutable, so a deploy with
// changed files gets new URLs and never fights Cloudflare's cache.
func (s *Server) loadStatic() error {
	h := sha256.New()
	entries, err := fs.ReadDir(webFS, "web/static")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, n := range names {
		b, err := webFS.ReadFile("web/static/" + n)
		if err != nil {
			return err
		}
		s.static[n] = b
		h.Write([]byte(n))
		h.Write(b)
	}
	s.assetHash = hex.EncodeToString(h.Sum(nil))[:12]
	return nil
}

// Handler is the full HTTP handler with the security middleware.
func (s *Server) Handler() http.Handler { return s.secure(s.mux) }

func (s *Server) routes() {
	m := http.NewServeMux()
	m.HandleFunc("GET /{$}", s.landing(copyEN))
	m.HandleFunc("GET /fa", s.landing(copyFA))
	m.HandleFunc("GET /static/{hash}/{file}", s.handleStatic)
	m.HandleFunc("GET /healthz", s.handleHealth)
	m.HandleFunc("GET /robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "User-agent: *\nDisallow: /admin\nDisallow: /login\n")
	})
	m.HandleFunc("GET /login", s.handleLoginForm)
	m.HandleFunc("POST /login", s.handleLogin)
	m.HandleFunc("POST /logout", s.handleLogout)
	m.HandleFunc("GET /admin", s.handleAdmin)
	s.mux = m
}

// secure adds the headers every response carries. The CSP allows nothing but
// our own styles and images: no scripts at all. Nothing is cacheable unless
// its handler says so (a cached redirect could loop a signed-in admin).
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
		defer func() {
			if rec := recover(); rec != nil {
				s.cfg.Logger.Error("handler panic", "panic", rec, "path", r.URL.Path)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		s.cfg.Logger.Error("render failed", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) landing(c siteCopy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		s.render(w, http.StatusOK, "landing.html", map[string]any{
			"T": c, "Releases": releasesURL, "SourceURL": sourceURL, "Year": s.cfg.Now().Year(),
		})
	}
}

// staticTypes is fixed rather than read from the host's mime database, which
// varies (and may not know fonts at all).
var staticTypes = map[string]string{
	".css": "text/css; charset=utf-8",
	".svg": "image/svg+xml",
	".png": "image/png",
	".ttf": "font/ttf",
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	b, ok := s.static[r.PathValue("file")]
	if !ok || r.PathValue("hash") != s.assetHash {
		http.NotFound(w, r)
		return
	}
	if ct := staticTypes[path.Ext(r.PathValue("file"))]; ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	_, _ = w.Write(b)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "ok", "version": buildinfo.Label(s.cfg.Build), "commit": buildinfo.ShortCommit(s.cfg.Build),
	})
}

// clientKey identifies a client for the login throttle only: Cloudflare's
// header when present (we sit behind Caddy on loopback, so RemoteAddr is
// always Caddy, and Caddy only accepts connections from Cloudflare). An IPv6
// address counts as its /64 — one subscriber usually holds a whole /64, so
// per-address keys would give one attacker billions of fresh clients.
func clientKey(r *http.Request) string {
	v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))
	if v == "" {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			v = strings.TrimSpace(strings.Split(xff, ",")[0])
		} else {
			v, _, _ = net.SplitHostPort(r.RemoteAddr)
		}
	}
	if ip := net.ParseIP(v); ip != nil && ip.To4() == nil {
		return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return v
}

// knownDevice returns the device's token hash when the request carries a
// device cookie issued at an earlier sign-in.
func (s *Server) knownDevice(r *http.Request) (string, bool) {
	c, err := r.Cookie(deviceCookie)
	if err != nil || c.Value == "" {
		return "", false
	}
	th := sha256hex(c.Value)
	return th, s.st.knownDevice(th, s.cfg.Now())
}

func setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: maxAge,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

// sessionFrom returns the session's token hash and CSRF token if the request
// carries a live session.
func (s *Server) sessionFrom(r *http.Request) (tokenHash, csrf string, ok bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return "", "", false
	}
	th := sha256hex(c.Value)
	csrf, ok, err = s.st.session(th, s.cfg.Now())
	if err != nil || !ok {
		return "", "", false
	}
	return th, csrf, true
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.sessionFrom(r); ok {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	s.loginPage(w, http.StatusOK, "")
}

func (s *Server) loginPage(w http.ResponseWriter, status int, msg string) {
	token := randomToken()
	setCookie(w, loginCSRF, token, 900)
	w.Header().Set("Cache-Control", "no-store")
	_, noPW := readPasswordHash(s.cfg.DataDir)
	s.render(w, status, "login.html", map[string]any{
		"CSRF": token, "Error": msg, "NoPassword": errors.Is(noPW, ErrNoPassword),
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	now := s.cfg.Now()
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	c, err := r.Cookie(loginCSRF)
	if err != nil || !equalTokens(c.Value, r.PostFormValue("csrf")) {
		s.loginPage(w, http.StatusForbidden, "Your session expired. Please try again.")
		return
	}
	// A known device is throttled on its own; everyone else by address and
	// against the global cap.
	client := clientKey(r)
	device, trusted := s.knownDevice(r)
	if trusted {
		client = "device:" + device
	}
	if !s.lim.begin(client, trusted, now) {
		s.loginPage(w, http.StatusTooManyRequests, "Too many attempts. Wait 15 minutes and try again.")
		return
	}
	hash, err := readPasswordHash(s.cfg.DataDir)
	if err != nil {
		s.lim.refund(client, trusted, now)
		if !errors.Is(err, ErrNoPassword) {
			s.cfg.Logger.Error("can't read the admin password file", "err", err)
		}
		s.loginPage(w, http.StatusServiceUnavailable, "Admin login isn't set up on this server yet.")
		return
	}
	// One password check at a time: each costs 64 MiB and real CPU on a
	// shared host. A request that can't get a turn soon gets its attempt back.
	wait := time.NewTimer(verifyWait)
	defer wait.Stop()
	select {
	case s.verify <- struct{}{}:
	case <-wait.C:
		s.lim.refund(client, trusted, now)
		s.loginPage(w, http.StatusServiceUnavailable, "The server is busy. Try again in a moment.")
		return
	case <-r.Context().Done():
		s.lim.refund(client, trusted, now)
		return
	}
	ok := VerifyPassword(hash, r.PostFormValue("password"))
	<-s.verify
	if !ok {
		s.cfg.Logger.Warn("admin login failed") // deliberately no client address
		s.loginPage(w, http.StatusUnauthorized, "Wrong password.")
		return
	}
	s.lim.succeeded(client, trusted, now)
	token := randomToken()
	if err := s.st.createSession(sha256hex(token), randomToken(), now, now.Add(sessionTTL)); err != nil {
		s.cfg.Logger.Error("session create failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if trusted {
		_ = s.st.touchDevice(device, now)
	} else {
		dt := randomToken()
		if err := s.st.addDevice(sha256hex(dt), now); err == nil {
			setCookie(w, deviceCookie, dt, int(deviceTTL.Seconds()))
		}
	}
	setCookie(w, loginCSRF, "", -1)
	setCookie(w, sessionCookie, token, int(sessionTTL.Seconds()))
	s.cfg.Logger.Info("admin signed in")
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	_ = r.ParseForm()
	th, csrf, ok := s.sessionFrom(r)
	if !ok || !equalTokens(csrf, r.PostFormValue("csrf")) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	_ = s.st.deleteSession(th)
	setCookie(w, sessionCookie, "", -1)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	_, csrf, ok := s.sessionFrom(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	now := s.cfg.Now()
	data := map[string]any{
		"CSRF":     csrf,
		"Version":  buildinfo.Short(s.cfg.Build),
		"Uptime":   now.Sub(s.started).Round(time.Second).String(),
		"DBSize":   s.st.size(),
		"Sessions": s.st.activeSessions(now),
	}
	if s.cfg.DiskFree != nil {
		if free, err := s.cfg.DiskFree(s.cfg.DataDir); err == nil {
			data["DiskFree"] = free
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, http.StatusOK, "admin.html", data)
}

func humanBytes(v any) string {
	var n float64
	switch x := v.(type) {
	case int64:
		n = float64(x)
	case uint64:
		n = float64(x)
	default:
		return fmt.Sprint(v)
	}
	for _, u := range []string{"B", "KB", "MB", "GB", "TB"} {
		if n < 1024 || u == "TB" {
			if u == "B" {
				return fmt.Sprintf("%.0f %s", n, u)
			}
			return fmt.Sprintf("%.1f %s", n, u)
		}
		n /= 1024
	}
	return ""
}
