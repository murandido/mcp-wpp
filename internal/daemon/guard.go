package daemon

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/murandido/mcp-wpp/internal/auth"
	"github.com/murandido/mcp-wpp/internal/oauth"
)

// Request guards, applied to every request in this order:
//
//  1. hostGuard rejects requests whose Host or Origin is not a loopback name
//     or an operator-allowed host. This defeats DNS rebinding: a hostile page
//     can resolve its own domain to 127.0.0.1, but the browser still sends
//     that domain in Host and Origin.
//  2. authGuard fails closed. Only the probes, the one-time UI login and
//     the OAuth endpoints (metadata, register, authorize, token, revoke)
//     are public. /admin/* accepts the operator bearer token only; /mcp accepts
//     it or a client API token (wpp-mcp token); browser pages accept the
//     operator bearer token or a session cookie minted by /ui/login. The
//     caller's auth.Identity travels on the request context.

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
	case path == "/healthz", path == "/readyz", path == loginPath, oauth.IsPublicPath(path):
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

// isMCPPath reports whether path is the MCP endpoint, the only place client
// tokens are accepted.
func isMCPPath(path string) bool { return path == "/mcp" || strings.HasPrefix(path, "/mcp/") }

// authGuard enforces the bearer token / session cookie policy and attaches
// the caller's auth.Identity to the request context. The operator token is
// accepted everywhere; client tokens (tokens may be nil) only on /mcp. A
// client token bound to an audience (an OAuth access token) is accepted only
// when that audience is the resource of the configured OAuth server (op may
// be nil, which refuses every such token). Every rejection, whatever the
// reason, is the same 401; on /mcp with OAuth it carries the RFC 9728
// resource_metadata challenge.
func authGuard(next http.Handler, token string, ui *uiAuth, tokens TokenVerifier, op OAuthProvider) http.Handler {
	expected := []byte("Bearer " + token)
	bearerOK := func(r *http.Request) bool {
		return token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), expected) == 1
	}
	clientToken := func(r *http.Request) (auth.Identity, bool) {
		if tokens == nil {
			return auth.Identity{}, false
		}
		plain, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || !auth.LooksLikeToken(plain) {
			return auth.Identity{}, false
		}
		t, err := tokens.VerifyAPIToken(r.Context(), plain)
		if err != nil {
			return auth.Identity{}, false
		}
		if t.Audience != "" && (op == nil || subtle.ConstantTimeCompare([]byte(t.Audience), []byte(op.Resource())) != 1) {
			return auth.Identity{}, false
		}
		return t.Identity(), true
	}
	challenge := `Bearer realm="wpp-mcp"`
	mcpChallenge := challenge
	if op != nil {
		mcpChallenge += fmt.Sprintf(`, resource_metadata=%q, scope="read"`, op.ResourceMetadataURL())
	}
	deny := func(w http.ResponseWriter, r *http.Request) {
		c := challenge
		if isMCPPath(r.URL.Path) {
			c = mcpChallenge
			if op != nil && r.Header.Get("Authorization") != "" {
				c += `, error="invalid_token"`
			}
		}
		w.Header().Set("WWW-Authenticate", c)
		http.Error(w, "unauthorized: run `wpp-mcp open-ui` for a browser login link", http.StatusUnauthorized)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var id auth.Identity
		switch classify(r.URL.Path) {
		case classPublic:
			next.ServeHTTP(w, r)
			return
		case classBearer:
			switch {
			case bearerOK(r):
				id = auth.Operator("bearer")
			case isMCPPath(r.URL.Path):
				var ok bool
				if id, ok = clientToken(r); !ok {
					deny(w, r)
					return
				}
			default:
				deny(w, r)
				return
			}
		case classBrowser:
			id = auth.Operator("bearer")
			if !bearerOK(r) {
				c, err := r.Cookie(sessionCookie)
				if err != nil || !ui.validSession(c.Value) {
					deny(w, r)
					return
				}
				id = auth.Operator("session")
			}
		}
		next.ServeHTTP(w, r.WithContext(auth.WithIdentity(r.Context(), id)))
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
		// Secure is set whenever the request arrived over HTTPS; the default
		// loopback listener is plain HTTP, where a Secure cookie would not be
		// stored by every browser.
		http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: see above
			Name:     sessionCookie,
			Value:    id,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
			MaxAge:   int(sessionTTL.Seconds()),
		})
		next, ok := landingPath(r.URL.Query().Get("next"))
		if !ok {
			next = defaultUILandIn
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		http.Redirect(w, r, next, http.StatusSeeOther) // next is a constant from landingPages
	})
}

// safeLanding accepts only local page paths, never another origin.
func safeLanding(p string) bool {
	_, ok := landingPath(p)
	return ok
}

// landingPages are the only post-login destinations. The redirect target
// is always one of these constants, never text taken from the request.
var landingPages = map[string]string{
	"/pair":   "/pair",
	"/access": "/access",
	"/outbox": "/outbox",
}

// landingPath maps a requested post-login destination to one of
// landingPages. Anything else, including other origins, other paths and
// query strings, is refused.
func landingPath(p string) (string, bool) {
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return "", false
	}
	target, ok := landingPages[u.Path]
	return target, ok
}
