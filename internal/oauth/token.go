package oauth

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/murandido/mcp-wpp/internal/store"
)

// tokenResponse is the RFC 6749 §5.1 success body.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// parseForm reads an application/x-www-form-urlencoded body of bounded
// size, refusing repeated parameters (RFC 6749 §3.2).
func parseForm(w http.ResponseWriter, r *http.Request) (map[string]string, bool) {
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(strings.ToLower(ct), "application/x-www-form-urlencoded") {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the body must be application/x-www-form-urlencoded")
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return nil, false
	}
	out := map[string]string{}
	for k, v := range r.PostForm {
		if len(v) > 1 {
			oauthError(w, http.StatusBadRequest, "invalid_request", "repeated parameter "+k)
			return nil, false
		}
		out[k] = v[0]
	}
	return out, true
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if !s.tokenLimit.allow(clientIP(r)) {
		w.Header().Set("Retry-After", "60")
		oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many token requests")
		return
	}
	f, ok := parseForm(w, r)
	if !ok {
		return
	}
	if res := f["resource"]; res != "" {
		if canon, ok := CanonicalResource(res); !ok || canon != s.resource {
			oauthError(w, http.StatusBadRequest, "invalid_target", "unknown resource")
			return
		}
	}
	// Clients are public. Some send their client_id as HTTP Basic with an
	// empty secret; accept that form, but never a secret, which this
	// server could not check.
	if id, secret, basic := r.BasicAuth(); basic {
		if secret != "" || (f["client_id"] != "" && f["client_id"] != id) {
			w.Header().Set("WWW-Authenticate", `Basic realm="wpp-mcp"`)
			oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication is not supported (public clients only)")
			return
		}
		f["client_id"] = id
	} else if r.Header.Get("Authorization") != "" {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication is not supported (public clients only)")
		return
	}
	if f["client_id"] == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}
	switch f["grant_type"] {
	case "authorization_code":
		s.exchangeCode(w, r, f)
	case "refresh_token":
		s.refresh(w, r, f)
	case "":
		oauthError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request, f map[string]string) {
	code, verifier := f["code"], f["code_verifier"]
	if code == "" || f["redirect_uri"] == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "code and redirect_uri are required")
		return
	}
	if !verifierPattern.MatchString(verifier) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "a valid PKCE code_verifier is required")
		return
	}
	h := hashCode(code)
	s.mu.Lock()
	s.prune()
	if red, replay := s.redeemed[h]; replay {
		// A code presented twice: revoke what it produced (RFC 6749 §4.1.2).
		delete(s.redeemed, h)
		s.mu.Unlock()
		if red.grantID != "" {
			_, _ = s.st.RevokeOAuthGrant(r.Context(), red.grantID, "authorization code replay")
			s.logf("oauth: authorization code replayed; grant %s revoked", red.grantID)
		}
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid authorization code")
		return
	}
	c, found := s.codes[h]
	if found {
		// Single use: whatever happens next, this code is spent.
		delete(s.codes, h)
		delete(s.pending, c.pendingID)
	}
	s.mu.Unlock()
	now := s.now()
	if !found || !now.Before(c.Expires) ||
		subtle.ConstantTimeCompare([]byte(f["client_id"]), []byte(c.ClientID)) != 1 ||
		f["redirect_uri"] != c.RedirectURI ||
		subtle.ConstantTimeCompare([]byte(pkceS256(verifier)), []byte(c.Challenge)) != 1 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid authorization code")
		return
	}
	toks, err := s.st.CreateOAuthGrant(r.Context(), store.NewOAuthGrant{
		ClientID: c.ClientID, ClientName: c.ClientName, RedirectURI: c.RedirectURI,
		Scopes: c.Scopes, Chats: c.Chats, Audience: s.resource, RefreshTTL: c.RefreshTTL,
	})
	if err != nil {
		if errors.Is(err, store.ErrOAuthLimit) {
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "too many active grants")
			return
		}
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	s.mu.Lock()
	s.redeemed[h] = redeemedCode{grantID: toks.Grant.ID, until: now.Add(codeTTL * 5)}
	s.mu.Unlock()
	s.logf("oauth: grant %s issued to client %q (scopes %s)", toks.Grant.ID, c.ClientName, strings.Join(toks.Scopes, ","))
	writeTokens(w, toks)
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request, f map[string]string) {
	rt := f["refresh_token"]
	if rt == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	var scopes []string
	if sc := strings.TrimSpace(f["scope"]); sc != "" {
		parsed, ok := parseScopeParam(sc)
		if !ok {
			oauthError(w, http.StatusBadRequest, "invalid_scope", "")
			return
		}
		scopes = parsed
	}
	toks, err := s.st.RefreshOAuthGrant(r.Context(), rt, f["client_id"], scopes)
	switch {
	case errors.Is(err, store.ErrOAuthGrantInvalid):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
		return
	case errors.Is(err, store.ErrOAuthScope):
		oauthError(w, http.StatusBadRequest, "invalid_scope", "the scope exceeds the grant")
		return
	case err != nil:
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	writeTokens(w, toks)
}

func writeTokens(w http.ResponseWriter, t store.OAuthTokens) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  t.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    t.ExpiresIn,
		RefreshToken: t.RefreshToken,
		Scope:        strings.Join(t.Scopes, " "),
	})
}

// handleRevoke implements RFC 7009. It answers 200 whether or not the token
// existed, so it cannot be used to probe tokens.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.tokenLimit.allow(clientIP(r)) {
		w.Header().Set("Retry-After", "60")
		oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many requests")
		return
	}
	f, ok := parseForm(w, r)
	if !ok {
		return
	}
	if f["token"] == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}
	if err := s.st.RevokeOAuthToken(r.Context(), f["token"], f["client_id"]); err != nil {
		s.logf("oauth: revoke: %v", err)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}
