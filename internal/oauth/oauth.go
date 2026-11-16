// Package oauth is the OAuth 2.1 authorization server for the remote MCP
// endpoint. It lets a connector such as claude.ai obtain short-lived,
// audience-bound client tokens without a pasted secret, while every
// connection is approved by the operator on the server:
//
//  1. The client discovers the server through RFC 9728 Protected Resource
//     Metadata and RFC 8414 Authorization Server Metadata.
//  2. It identifies itself with a Client ID Metadata Document (an https
//     client_id fetched with SSRF protection) or registers through RFC 7591
//     Dynamic Client Registration.
//  3. GET /oauth/authorize validates the request (exact redirect URI from
//     the allowlist, PKCE S256, RFC 8707 resource, scopes) and shows a page
//     with a short code. Nothing is approved there: the page has no buttons
//     and the flow has no password.
//  4. The operator runs `wpp-mcp oauth approve <code>` on the server (the
//     bearer-only admin API), optionally narrowing scopes and chats.
//  5. The page polls an opaque request ID, receives the redirect with a
//     single-use authorization code, and the client redeems it with its PKCE
//     verifier at /oauth/token.
//
// Access tokens are api_tokens rows bound to the resource (audience) and
// valid for an hour; refresh tokens rotate on every use and a reused one
// revokes the grant. Redirects only ever go to a URI from the operator's
// allowlist, taken from configuration rather than from the request.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/murandido/mcp-wpp/internal/auth"
	"github.com/murandido/mcp-wpp/internal/store"
)

// DefaultRedirectURI is claude.ai's connector callback, the default and
// only entry of the redirect allowlist unless the operator changes it.
const DefaultRedirectURI = "https://claude.ai/api/mcp/auth_callback"

// Paths served by the package. Everything under /oauth/ and the well-known
// documents is public; /admin/oauth/* is the operator API.
const (
	PathResourceMetadata      = "/.well-known/oauth-protected-resource"
	PathResourceMetadataMCP   = "/.well-known/oauth-protected-resource/mcp"
	PathAuthServerMetadata    = "/.well-known/oauth-authorization-server"
	PathRegister              = "/oauth/register"
	PathAuthorize             = "/oauth/authorize"
	PathAuthorizeStatus       = "/oauth/authorize/status"
	PathToken                 = "/oauth/token" //nolint:gosec // G101: a URL path, not a credential
	PathRevoke                = "/oauth/revoke"
	resourcePath              = "/mcp"
	maxFormBytes              = 64 << 10
	pendingTTL                = 10 * time.Minute
	pendingKeep               = 5 * time.Minute // how long a finished request still answers status
	codeTTL                   = 60 * time.Second
	maxPending                = 20
	maxDCRClients             = 100
	cimdCacheTTL              = time.Hour
	authorizePerIP            = 10 // per authorizeWindow
	authorizeWindow           = 10 * time.Minute
	registerPerIP             = 10 // per registerWindow
	registerWindow            = time.Hour
	tokenPerIP                = 60 // per tokenWindow
	tokenWindow               = time.Minute
	defaultResourceName       = "wpp-mcp"
	scopeOfflineAccessIgnored = "offline_access"
)

// IsPublicPath reports whether path is one of the unauthenticated OAuth
// endpoints. The daemon's guard admits exactly these without credentials.
func IsPublicPath(path string) bool {
	switch path {
	case PathResourceMetadata, PathResourceMetadataMCP, PathAuthServerMetadata,
		PathRegister, PathAuthorize, PathAuthorizeStatus, PathToken, PathRevoke:
		return true
	}
	return false
}

// Store is the persistence the server needs. *store.Store satisfies it.
type Store interface {
	PutOAuthClient(ctx context.Context, c store.OAuthClient, cimdTTL time.Duration) error
	GetOAuthClient(ctx context.Context, id string) (store.OAuthClient, error)
	CountOAuthClients(ctx context.Context, kind string) (int, error)
	CreateOAuthGrant(ctx context.Context, in store.NewOAuthGrant) (store.OAuthTokens, error)
	RefreshOAuthGrant(ctx context.Context, refresh, clientID string, scopes []string) (store.OAuthTokens, error)
	RevokeOAuthGrant(ctx context.Context, id, reason string) (store.OAuthGrant, error)
	RevokeOAuthToken(ctx context.Context, token, clientID string) error
	ListOAuthGrants(ctx context.Context) ([]store.OAuthGrant, error)
}

// Config configures a Server.
type Config struct {
	// PublicURL is the https origin clients reach the daemon at, without a
	// path. It is the issuer; the protected resource is PublicURL + "/mcp".
	PublicURL string
	// RedirectURIs is the redirect allowlist. Empty means DefaultRedirectURI.
	RedirectURIs []string
	Store        Store
	// Logf, when set, receives operator-facing events (never secrets).
	Logf func(format string, args ...any)
	// Now and HTTPClient are for tests.
	Now        func() time.Time
	HTTPClient *http.Client
}

// Server is the authorization server and the resource metadata endpoint.
type Server struct {
	issuer    string
	resource  string
	redirects []string
	st        Store
	logf      func(string, ...any)
	now       func() time.Time
	fetch     *http.Client

	mu       sync.Mutex
	pending  map[string]*pendingRequest // by opaque ID
	codes    map[string]*authCode       // by SHA-256 hex of the code
	redeemed map[string]redeemedCode    // by SHA-256 hex, for replay detection

	authorizeLimit *ipLimiter
	registerLimit  *ipLimiter
	tokenLimit     *ipLimiter
}

// New validates cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	issuer, err := ParsePublicURL(cfg.PublicURL)
	if err != nil {
		return nil, err
	}
	if cfg.Store == nil {
		return nil, errors.New("oauth: Store required")
	}
	redirects := cfg.RedirectURIs
	if len(redirects) == 0 {
		redirects = []string{DefaultRedirectURI}
	}
	for _, r := range redirects {
		if err := validRedirectURI(r); err != nil {
			return nil, err
		}
	}
	s := &Server{
		issuer:         issuer,
		resource:       issuer + resourcePath,
		redirects:      append([]string(nil), redirects...),
		st:             cfg.Store,
		logf:           cfg.Logf,
		now:            cfg.Now,
		fetch:          cfg.HTTPClient,
		pending:        map[string]*pendingRequest{},
		codes:          map[string]*authCode{},
		redeemed:       map[string]redeemedCode{},
		authorizeLimit: newIPLimiter(authorizePerIP, authorizeWindow),
		registerLimit:  newIPLimiter(registerPerIP, registerWindow),
		tokenLimit:     newIPLimiter(tokenPerIP, tokenWindow),
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.logf == nil {
		s.logf = func(string, ...any) {}
	}
	if s.fetch == nil {
		s.fetch = NewFetchClient()
	}
	s.authorizeLimit.now, s.registerLimit.now, s.tokenLimit.now = s.clock, s.clock, s.clock
	return s, nil
}

func (s *Server) clock() time.Time { return s.now() }

// Issuer is the authorization server identifier (the public URL).
func (s *Server) Issuer() string { return s.issuer }

// Resource is the canonical protected resource, <public URL>/mcp. Access
// tokens carry it as their audience.
func (s *Server) Resource() string { return s.resource }

// ResourceMetadataURL is the RFC 9728 metadata URL for Resource, used in
// the WWW-Authenticate challenge of /mcp.
func (s *Server) ResourceMetadataURL() string { return s.issuer + PathResourceMetadataMCP }

// RedirectURIs returns the allowlist.
func (s *Server) RedirectURIs() []string { return append([]string(nil), s.redirects...) }

// Mount registers the public endpoints and the operator API on mux.
func (s *Server) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET "+PathResourceMetadata, s.handleResourceMetadata)
	mux.HandleFunc("GET "+PathResourceMetadataMCP, s.handleResourceMetadata)
	mux.HandleFunc("GET "+PathAuthServerMetadata, s.handleAuthServerMetadata)
	mux.HandleFunc("POST "+PathRegister, s.handleRegister)
	mux.HandleFunc("GET "+PathAuthorize, s.handleAuthorize)
	mux.HandleFunc("GET "+PathAuthorizeStatus, s.handleStatus)
	mux.HandleFunc("POST "+PathToken, s.handleToken)
	mux.HandleFunc("POST "+PathRevoke, s.handleRevoke)
	s.mountAdmin(mux)
}

// ResourceMetadata is the RFC 9728 document.
type ResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name,omitempty"`
}

// AuthServerMetadata is the RFC 8414 document.
type AuthServerMetadata struct {
	Issuer                                 string   `json:"issuer"`
	AuthorizationEndpoint                  string   `json:"authorization_endpoint"`
	TokenEndpoint                          string   `json:"token_endpoint"`
	RegistrationEndpoint                   string   `json:"registration_endpoint"`
	RevocationEndpoint                     string   `json:"revocation_endpoint"`
	ResponseTypesSupported                 []string `json:"response_types_supported"`
	ResponseModesSupported                 []string `json:"response_modes_supported"`
	GrantTypesSupported                    []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported          []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported      []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported"`
	ScopesSupported                        []string `json:"scopes_supported"`
	ClientIDMetadataDocumentSupported      bool     `json:"client_id_metadata_document_supported"`
	AuthorizationResponseIssParameter      bool     `json:"authorization_response_iss_parameter_supported"`
}

var supportedScopes = []string{auth.ScopeRead, auth.ScopeSend}

// ResourceMetadataDoc returns the protected resource metadata.
func (s *Server) ResourceMetadataDoc() ResourceMetadata {
	return ResourceMetadata{
		Resource:               s.resource,
		AuthorizationServers:   []string{s.issuer},
		ScopesSupported:        supportedScopes,
		BearerMethodsSupported: []string{"header"},
		ResourceName:           defaultResourceName,
	}
}

// AuthServerMetadataDoc returns the authorization server metadata.
func (s *Server) AuthServerMetadataDoc() AuthServerMetadata {
	return AuthServerMetadata{
		Issuer:                                 s.issuer,
		AuthorizationEndpoint:                  s.issuer + PathAuthorize,
		TokenEndpoint:                          s.issuer + PathToken,
		RegistrationEndpoint:                   s.issuer + PathRegister,
		RevocationEndpoint:                     s.issuer + PathRevoke,
		ResponseTypesSupported:                 []string{"code"},
		ResponseModesSupported:                 []string{"query"},
		GrantTypesSupported:                    []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:          []string{"S256"},
		TokenEndpointAuthMethodsSupported:      []string{"none"},
		RevocationEndpointAuthMethodsSupported: []string{"none"},
		ScopesSupported:                        supportedScopes,
		ClientIDMetadataDocumentSupported:      true,
		AuthorizationResponseIssParameter:      true,
	}
}

func (s *Server) handleResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, http.StatusOK, s.ResourceMetadataDoc())
}

func (s *Server) handleAuthServerMetadata(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, http.StatusOK, s.AuthServerMetadataDoc())
}

// --- configuration helpers --------------------------------------------------

// ParsePublicURL validates and canonicalises the public URL: https, a host,
// no path (a single trailing slash is dropped), no query, fragment or user
// info. The scheme and host are lowercased.
func ParsePublicURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("a public URL is required (-public-url https://host)")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("public URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("public URL %q must be https://host[:port] without user info, query or fragment", raw)
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("public URL %q must not have a path: the MCP endpoint is always <public URL>/mcp", raw)
	}
	return "https://" + strings.TrimSuffix(strings.ToLower(u.Host), ":443"), nil
}

// CanonicalResource normalises a resource indicator for comparison:
// lowercase scheme and host, no trailing slash, the default https port
// dropped. It refuses fragments, queries and non-absolute URIs.
func CanonicalResource(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" || u.RawQuery != "" || u.User != nil || u.Opaque != "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	if scheme == "https" {
		host = strings.TrimSuffix(host, ":443")
	}
	return scheme + "://" + host + strings.TrimRight(u.EscapedPath(), "/"), true
}

// ParseRedirectURIs parses a comma-separated allowlist. Empty means the
// default.
func ParseRedirectURIs(s string) ([]string, error) {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if err := validRedirectURI(p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		out = []string{DefaultRedirectURI}
	}
	return out, nil
}

// validRedirectURI accepts absolute https URIs, and http only on loopback
// (for local development clients), without fragments or user info.
func validRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" || u.User != nil || u.Opaque != "" {
		return fmt.Errorf("redirect URI %q must be an absolute URL without fragment or user info", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return fmt.Errorf("redirect URI %q must be https (http is allowed only on loopback)", raw)
}

// allowedRedirect returns the allowlist entry equal to requested. The
// returned string comes from configuration, never from the request, so a
// redirect built from it cannot be steered elsewhere.
func (s *Server) allowedRedirect(requested string) (string, bool) {
	for _, a := range s.redirects {
		if a == requested {
			return a, true
		}
	}
	return "", false
}

// --- small HTTP helpers ------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// oauthError writes an RFC 6749 §5.2 error.
func oauthError(w http.ResponseWriter, code int, errCode, desc string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	body := map[string]string{"error": errCode}
	if desc != "" {
		body["error_description"] = desc
	}
	writeJSON(w, code, body)
}

// clientIP returns the caller's address. When the peer is a reverse proxy on
// the same host or network (a loopback, private or Unix socket peer, as with
// Caddy in front or Docker's port proxy), the rightmost X-Forwarded-For
// entry, which that proxy appended, is used instead. Only rate limiting and
// the operator's `oauth pending` view depend on it.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	trusted := host == "" || host == "@" || (ip != nil && (ip.IsLoopback() || ip.IsPrivate()))
	if trusted {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if last := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); last != nil {
				return last.String()
			}
		}
	}
	if ip != nil {
		return ip.String()
	}
	if host == "" || host == "@" {
		return "local"
	}
	return host
}

// ipLimiter allows n events per window per IP, with a bounded memory.
type ipLimiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	seen   map[string][]time.Time
	now    func() time.Time
}

const maxLimiterIPs = 4096

func newIPLimiter(n int, window time.Duration) *ipLimiter {
	return &ipLimiter{n: n, window: window, seen: map[string][]time.Time{}, now: time.Now}
}

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cut := now.Add(-l.window)
	keep := func(ts []time.Time) []time.Time {
		out := ts[:0]
		for _, t := range ts {
			if t.After(cut) {
				out = append(out, t)
			}
		}
		return out
	}
	if len(l.seen) >= maxLimiterIPs {
		for k, ts := range l.seen {
			if ts = keep(ts); len(ts) == 0 {
				delete(l.seen, k)
			} else {
				l.seen[k] = ts
			}
		}
		if len(l.seen) >= maxLimiterIPs {
			return false
		}
	}
	ts := keep(l.seen[ip])
	if len(ts) >= l.n {
		l.seen[ip] = ts
		return false
	}
	l.seen[ip] = append(ts, now)
	return true
}
