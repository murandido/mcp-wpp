package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/murandido/mcp-wpp/internal/auth"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

var (
	authorizeTmpl = template.Must(template.ParseFS(templateFS, "templates/authorize.html.tmpl"))
	errorTmpl     = template.Must(template.ParseFS(templateFS, "templates/error.html.tmpl"))
)

type requestState int

const (
	statePending requestState = iota
	stateApproved
	stateDenied
)

// pendingRequest is an authorization request waiting for the operator. It
// has two identifiers: ID, a 128-bit secret known only to the browser page
// (it polls with it and receives the code), and Code, the short code the
// operator types. The short code alone cannot complete anything.
type pendingRequest struct {
	ID          string
	Code        string
	Client      client
	RedirectURI string // an allowlist entry
	State       string
	Challenge   string
	Scopes      []string
	SourceIP    string
	Created     time.Time
	Expires     time.Time

	state      requestState
	approved   []string // scopes
	chats      []string
	refreshTTL time.Duration
	authCode   string // minted when the page first sees the approval
	codeExp    time.Time
}

// authCode is an issued authorization code.
type authCode struct {
	ClientID    string
	ClientName  string
	RedirectURI string
	Challenge   string
	Scopes      []string
	Chats       []string
	RefreshTTL  time.Duration
	Expires     time.Time
	pendingID   string
}

type redeemedCode struct {
	grantID string
	until   time.Time
}

// codeAlphabet leaves out 0, 1, I and O: 32 symbols, 5 bits each.
const codeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// newShortCode returns 8 symbols (40 bits) as XXXX-XXXX.
func newShortCode() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, 0, 9)
	for i, v := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, codeAlphabet[v&31])
	}
	return string(out), nil
}

// NormalizeCode uppercases a short code and restores the dash.
func NormalizeCode(c string) string {
	c = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(c)))
	if len(c) != 8 {
		return c
	}
	return c[:4] + "-" + c[4:]
}

func randomID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// pkceS256 returns BASE64URL(SHA256(verifier)).
func pkceS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

var (
	challengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	verifierPattern  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
)

// parseScopeParam parses a space-separated scope parameter. Empty means
// read. send implies read. offline_access is ignored (refresh tokens are
// always issued). Anything else is an error.
func parseScopeParam(s string) ([]string, bool) {
	var parts []string
	for _, p := range strings.Fields(s) {
		if p == scopeOfflineAccessIgnored {
			continue
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return []string{auth.ScopeRead}, true
	}
	if !slices.Contains(parts, auth.ScopeRead) {
		parts = append(parts, auth.ScopeRead)
	}
	scopes, err := auth.ParseScopes(strings.Join(parts, ","))
	return scopes, err == nil
}

// prune drops finished and expired requests and codes. Callers hold s.mu.
func (s *Server) prune() {
	now := s.now()
	for id, p := range s.pending {
		if now.After(p.Expires.Add(pendingKeep)) || (p.authCode != "" && now.After(p.codeExp.Add(pendingKeep))) {
			delete(s.pending, id)
		}
	}
	for h, c := range s.codes {
		if now.After(c.Expires) {
			delete(s.codes, h)
		}
	}
	for h, r := range s.redeemed {
		if now.After(r.until) {
			delete(s.redeemed, h)
		}
	}
}

// openRequests counts requests still waiting for the operator.
func (s *Server) openRequests() int {
	now := s.now()
	n := 0
	for _, p := range s.pending {
		if p.state == statePending && now.Before(p.Expires) {
			n++
		}
	}
	return n
}

// redirectTo builds a redirect to an allowlist entry with params. base is
// always a value from s.redirects.
func (s *Server) redirectTo(base string, params url.Values) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	q.Set("iss", s.issuer)
	u.RawQuery = q.Encode()
	return u.String()
}

func (s *Server) errorRedirect(base, errCode, desc, state string) string {
	p := url.Values{"error": {errCode}}
	if desc != "" {
		p.Set("error_description", desc)
	}
	if state != "" {
		p.Set("state", state)
	}
	return s.redirectTo(base, p)
}

// errorPage renders a problem that must not be redirected (unknown client
// or redirect URI).
func errorPage(w http.ResponseWriter, code int, msg string) {
	setPageHeaders(w, "")
	w.WriteHeader(code)
	_ = errorTmpl.Execute(w, map[string]string{"Message": msg})
}

func setPageHeaders(w http.ResponseWriter, nonce string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	csp := "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	if nonce != "" {
		csp += "; script-src 'nonce-" + nonce + "'; connect-src 'self'"
	}
	h.Set("Content-Security-Policy", csp)
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeLimit.allow(clientIP(r)) {
		w.Header().Set("Retry-After", "600")
		errorPage(w, http.StatusTooManyRequests, "Too many authorization requests from your address. Wait a few minutes and try again.")
		return
	}
	q := r.URL.Query()
	for _, k := range []string{"client_id", "redirect_uri", "response_type", "state", "code_challenge", "code_challenge_method", "scope", "resource"} {
		if len(q[k]) > 1 {
			errorPage(w, http.StatusBadRequest, "The authorization request repeats the parameter "+k+".")
			return
		}
	}
	// Until client and redirect URI are validated, every problem is shown
	// here and nothing is redirected.
	c, err := s.resolveClient(r.Context(), q.Get("client_id"))
	if err != nil {
		msg := "The client could not be identified."
		if e, ok := err.(errClient); ok {
			msg = "The client could not be identified: " + e.msg + "."
		}
		errorPage(w, http.StatusBadRequest, msg)
		return
	}
	requested := q.Get("redirect_uri")
	redirect, allowed := s.allowedRedirect(requested)
	if !allowed || !slices.Contains(c.RedirectURIs, requested) {
		errorPage(w, http.StatusBadRequest, "The redirect URI is not allowed for this client or by this server.")
		return
	}
	state := q.Get("state")
	fail := func(code, desc string) {
		http.Redirect(w, r, s.errorRedirect(redirect, code, desc, state), http.StatusFound)
	}
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only response_type=code is supported")
		return
	}
	challenge := q.Get("code_challenge")
	if q.Get("code_challenge_method") != "S256" || !challengePattern.MatchString(challenge) {
		fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	}
	if res := q.Get("resource"); res != "" {
		if canon, ok := CanonicalResource(res); !ok || canon != s.resource {
			fail("invalid_target", "unknown resource")
			return
		}
	}
	scopes, ok := parseScopeParam(q.Get("scope"))
	if !ok {
		fail("invalid_scope", "supported scopes are read and send")
		return
	}

	id, err := randomID(16)
	if err != nil {
		fail("server_error", "")
		return
	}
	code, err := newShortCode()
	if err != nil {
		fail("server_error", "")
		return
	}
	now := s.now()
	p := &pendingRequest{
		ID: id, Code: code, Client: c, RedirectURI: redirect, State: state, Challenge: challenge,
		Scopes: scopes, SourceIP: clientIP(r), Created: now, Expires: now.Add(pendingTTL),
	}
	s.mu.Lock()
	s.prune()
	if s.openRequests() >= maxPending {
		s.mu.Unlock()
		fail("temporarily_unavailable", "too many pending authorization requests")
		return
	}
	for _, other := range s.pending {
		if other.Code == code { // 40 bits: practically never
			s.mu.Unlock()
			fail("server_error", "")
			return
		}
	}
	s.pending[id] = p
	s.mu.Unlock()

	s.logf("oauth: authorization request %s from client %q (redirect host %s, source %s, scopes %s); approve with `wpp-mcp oauth approve %s`",
		code, c.Name, redirectHost(redirect), p.SourceIP, strings.Join(scopes, ","), code)

	nonce, _ := randomID(16)
	setPageHeaders(w, nonce)
	_ = authorizeTmpl.Execute(w, map[string]any{
		"ClientName":   c.Name,
		"ClientID":     c.ID,
		"RedirectHost": redirectHost(redirect),
		"Scopes":       scopes,
		"Code":         code,
		"RequestID":    id,
		"StatusPath":   PathAuthorizeStatus,
		"Minutes":      int(pendingTTL.Minutes()),
		"Nonce":        nonce,
	})
}

func redirectHost(u string) string {
	if p, err := url.Parse(u); err == nil {
		return p.Host
	}
	return ""
}

// statusResponse is what the authorization page polls.
type statusResponse struct {
	Status    string `json:"status"` // pending, approved, denied, unknown
	Redirect  string `json:"redirect,omitempty"`
	ExpiresIn int    `json:"expires_in,omitempty"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("req")
	s.mu.Lock()
	s.prune()
	p, ok := s.pending[id]
	if !ok || id == "" {
		s.mu.Unlock()
		writeJSON(w, http.StatusNotFound, statusResponse{Status: "unknown"})
		return
	}
	now := s.now()
	var resp statusResponse
	switch {
	case p.state == stateApproved && p.authCode == "":
		code, err := randomID(32)
		if err != nil {
			s.mu.Unlock()
			writeJSON(w, http.StatusInternalServerError, statusResponse{Status: "unknown"})
			return
		}
		p.authCode, p.codeExp = code, now.Add(codeTTL)
		s.codes[hashCode(code)] = &authCode{
			ClientID: p.Client.ID, ClientName: p.Client.Name, RedirectURI: p.RedirectURI, Challenge: p.Challenge,
			Scopes: p.approved, Chats: p.chats, RefreshTTL: p.refreshTTL, Expires: p.codeExp, pendingID: p.ID,
		}
		resp = statusResponse{Status: "approved", Redirect: s.successRedirect(p)}
	case p.state == stateApproved && now.Before(p.codeExp):
		resp = statusResponse{Status: "approved", Redirect: s.successRedirect(p)}
	case p.state == stateDenied || p.state == stateApproved || !now.Before(p.Expires):
		resp = statusResponse{Status: "denied", Redirect: s.errorRedirect(p.RedirectURI, "access_denied", "the request was denied or expired", p.State)}
	default:
		resp = statusResponse{Status: "pending", ExpiresIn: int(p.Expires.Sub(now).Seconds())}
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) successRedirect(p *pendingRequest) string {
	params := url.Values{"code": {p.authCode}}
	if p.State != "" {
		params.Set("state", p.State)
	}
	return s.redirectTo(p.RedirectURI, params)
}
