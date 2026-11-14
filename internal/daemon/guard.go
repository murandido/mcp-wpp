package daemon

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Request guards, applied to every request in this order:
//
//  1. hostGuard rejects requests whose Host or Origin is not a loopback name
//     or an operator-allowed host. This defeats DNS rebinding: a hostile page
//     can resolve its own domain to 127.0.0.1, but the browser still sends
//     that domain in Host and Origin.
//  2. authGuard fails closed. Only the probes and the one-time UI login are
//     public. /mcp and /admin/* accept the bearer token only; browser pages
//     accept the bearer token or a session cookie minted by /ui/login.

const (
	sessionCookie   = "wpp_mcp_session"
	sessionTTL      = 12 * time.Hour
	loginCodeTTL    = 2 * time.Minute
	maxLoginCodes   = 16
	maxUISessions   = 64
	loginPath       = "/ui/login"
	adminLoginPath  = "/admin/ui-login"
	defaultUILandIn = "/pair"
)

// loopbackHosts are always accepted in Host and Origin, on any port: a
// rebinding attacker controls the hostname, never these literals.
var loopbackHosts = map[string]bool{
	"localhost": true,
	"127.0.0.1": true,
	"::1":       true,
}

// hostGuard returns a handler that admits only loopback or explicitly allowed
// hosts. allowed entries are either a bare hostname (any port) or host:port.
func hostGuard(next http.Handler, allowed []string) http.Handler {
	allow := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		a = strings.ToLower(strings.TrimSpace(a))
		if a != "" {
			allow[a] = true
		}
	}
	ok := func(hostport string) bool {
		hostport = strings.ToLower(hostport)
		if allow[hostport] {
			return true
		}
		host := hostport
		if h, _, err := net.SplitHostPort(hostport); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		return loopbackHosts[host] || allow[host]
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ok(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !ok(u.Host) {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// pathClass decides which credentials a path accepts.
type pathClass int

const (
	classPublic pathClass = iota
	classBearer
	classBrowser
)

func classify(path string) pathClass {
	switch {
	case path == "/healthz", path == "/readyz", path == loginPath:
		return classPublic
	case path == "/mcp", strings.HasPrefix(path, "/mcp/"),
		path == "/admin", strings.HasPrefix(path, "/admin/"):
		return classBearer
	default:
		// Pages and anything unknown: fail closed.
		return classBrowser
	}
}

// uiAuth holds one-time login codes and browser sessions. Everything is in
// memory: a daemon restart logs every browser out, which is the safe default.
type uiAuth struct {
	mu       sync.Mutex
	codes    map[string]time.Time
	sessions map[string]time.Time
	now      func() time.Time
}

func newUIAuth() *uiAuth {
	return &uiAuth{codes: map[string]time.Time{}, sessions: map[string]time.Time{}, now: time.Now}
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func (a *uiAuth) prune(m map[string]time.Time, limit int) {
	now := a.now()
	for k, exp := range m {
		if now.After(exp) {
			delete(m, k)
		}
	}
	// Bound memory: drop arbitrary entries beyond the cap.
	for k := range m {
		if len(m) <= limit {
			break
		}
		delete(m, k)
	}
}

// mintCode returns a single-use login code valid for loginCodeTTL.
func (a *uiAuth) mintCode() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prune(a.codes, maxLoginCodes-1)
	code := randomToken()
	a.codes[code] = a.now().Add(loginCodeTTL)
	return code
}

// redeem consumes code and, if valid, returns a new session ID.
func (a *uiAuth) redeem(code string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.codes[code]
	if !ok || code == "" {
		return "", false
	}
	delete(a.codes, code)
	if a.now().After(exp) {
		return "", false
	}
	a.prune(a.sessions, maxUISessions-1)
	id := randomToken()
	a.sessions[id] = a.now().Add(sessionTTL)
	return id, true
}

func (a *uiAuth) validSession(id string) bool {
	if id == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sessions[id]
	if !ok {
		return false
	}
	if a.now().After(exp) {
		delete(a.sessions, id)
		return false
	}
	return true
}

// authGuard enforces the bearer token / session cookie policy.
func authGuard(next http.Handler, token string, ui *uiAuth) http.Handler {
	expected := []byte("Bearer " + token)
	bearerOK := func(r *http.Request) bool {
		return token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), expected) == 1
	}
	deny := func(w http.ResponseWriter) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="wpp-mcp"`)
		http.Error(w, "unauthorized: run `wpp-mcp open-ui` for a browser login link", http.StatusUnauthorized)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch classify(r.URL.Path) {
		case classPublic:
		case classBearer:
			if !bearerOK(r) {
				deny(w)
				return
			}
		case classBrowser:
			if !bearerOK(r) {
				c, err := r.Cookie(sessionCookie)
				if err != nil || !ui.validSession(c.Value) {
					deny(w)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// mountUIAuth registers the admin code-minting endpoint and the browser
// login endpoint.
func (a *uiAuth) mount(mux *http.ServeMux) {
	mux.HandleFunc("POST "+adminLoginPath, func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if !safeLanding(next) {
			next = defaultUILandIn
		}
		q := url.Values{"code": {a.mintCode()}, "next": {next}}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"path":       loginPath + "?" + q.Encode(),
			"expires_in": int(loginCodeTTL.Seconds()),
		})
	})
	mux.HandleFunc("GET "+loginPath, func(w http.ResponseWriter, r *http.Request) {
		id, ok := a.redeem(r.URL.Query().Get("code"))
		if !ok {
			http.Error(w, "login link is invalid or expired: run `wpp-mcp open-ui` again", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    id,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
			MaxAge:   int(sessionTTL.Seconds()),
		})
		next := r.URL.Query().Get("next")
		if !safeLanding(next) {
			next = defaultUILandIn
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		http.Redirect(w, r, next, http.StatusSeeOther)
	})
}

// safeLanding accepts only local page paths, never another origin.
func safeLanding(p string) bool {
	if p == "" || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.Contains(p, `\`) {
		return false
	}
	switch classify(strings.SplitN(p, "?", 2)[0]) {
	case classBrowser:
		return true
	default:
		return false
	}
}
