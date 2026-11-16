package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/murandido/mcp-wpp/internal/auth"
	"github.com/murandido/mcp-wpp/internal/store"
)

// Operator API, under /admin/oauth/ (bearer token only; the daemon's guard
// enforces it and its audit middleware records every POST):
//
//	GET  /admin/oauth/pending             requests waiting for approval
//	POST /admin/oauth/approve             {"code", "scopes"?, "chats"?, "days"?}
//	POST /admin/oauth/deny                {"code"}
//	GET  /admin/oauth/grants              approved connections
//	POST /admin/oauth/grants/{id}/revoke  revoke one, with its tokens

// PendingView is a pending request as the operator sees it.
type PendingView struct {
	Code         string    `json:"code"`
	ClientName   string    `json:"client_name"`
	ClientID     string    `json:"client_id"`
	ClientKind   string    `json:"client_kind"`
	RedirectHost string    `json:"redirect_host"`
	Scopes       []string  `json:"scopes"`
	SourceIP     string    `json:"source_ip"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresIn    int       `json:"expires_in"`
	// Set on an approval response.
	ApprovedScopes []string `json:"approved_scopes,omitempty"`
	ApprovedChats  []string `json:"approved_chats,omitempty"`
	RefreshDays    int      `json:"refresh_days,omitempty"`
}

// ApproveRequest is the operator's decision. Empty Scopes means the scopes
// the client requested; nil Chats means every chat the access policy
// allows; Days (default 30) is how long the grant's refresh token lasts
// without use.
type ApproveRequest struct {
	Code   string   `json:"code"`
	Scopes []string `json:"scopes,omitempty"`
	Chats  []string `json:"chats,omitempty"`
	Days   int      `json:"days,omitempty"`
}

// GrantView is a grant with its status.
type GrantView struct {
	store.OAuthGrant
	Status string `json:"status"`
}

var errNoRequest = errors.New("no pending authorization request with that code (it may have expired)")

func (s *Server) view(p *pendingRequest) PendingView {
	return PendingView{
		Code: p.Code, ClientName: p.Client.Name, ClientID: p.Client.ID, ClientKind: p.Client.Kind,
		RedirectHost: redirectHost(p.RedirectURI), Scopes: p.Scopes, SourceIP: p.SourceIP,
		CreatedAt: p.Created.UTC(), ExpiresIn: int(p.Expires.Sub(s.now()).Seconds()),
	}
}

// Pending lists the requests waiting for the operator, oldest first.
func (s *Server) Pending() []PendingView {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	now := s.now()
	var out []PendingView
	for _, p := range s.pending {
		if p.state == statePending && now.Before(p.Expires) {
			out = append(out, s.view(p))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// lookup returns the open request with the short code. Callers hold s.mu.
func (s *Server) lookup(code string) (*pendingRequest, error) {
	code = NormalizeCode(code)
	now := s.now()
	for _, p := range s.pending {
		if p.Code == code && p.state == statePending && now.Before(p.Expires) {
			return p, nil
		}
	}
	return nil, errNoRequest
}

// Approve approves the request with the short code. The operator's scopes
// and chats win over what the client asked for; without them the requested
// scopes and the access policy's chats apply. The page that started the
// request then receives an authorization code.
func (s *Server) Approve(in ApproveRequest) (PendingView, error) {
	scopes := in.Scopes
	if len(scopes) > 0 {
		parsed, err := auth.ParseScopes(strings.Join(scopes, ","))
		if err != nil {
			return PendingView{}, err
		}
		scopes = parsed
	}
	var chats []string
	if len(in.Chats) > 0 {
		parsed, err := auth.ParseChats(strings.Join(in.Chats, ","))
		if err != nil {
			return PendingView{}, err
		}
		chats = parsed
	}
	days := in.Days
	if days == 0 {
		days = int(store.OAuthDefaultRefreshTTL.Hours() / 24)
	}
	if days < 1 || time.Duration(days)*24*time.Hour > store.OAuthMaxRefreshTTL {
		return PendingView{}, fmt.Errorf("days must be between 1 and %d", int(store.OAuthMaxRefreshTTL.Hours()/24))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	p, err := s.lookup(in.Code)
	if err != nil {
		return PendingView{}, err
	}
	if len(scopes) == 0 {
		scopes = slices.Clone(p.Scopes)
	}
	p.state, p.approved, p.chats, p.refreshTTL = stateApproved, scopes, chats, time.Duration(days)*24*time.Hour
	v := s.view(p)
	v.ApprovedScopes, v.ApprovedChats, v.RefreshDays = scopes, chats, days
	s.logf("oauth: request %s approved (scopes %s)", p.Code, strings.Join(scopes, ","))
	return v, nil
}

// Deny refuses the request with the short code; the page sends the client
// back with access_denied.
func (s *Server) Deny(code string) (PendingView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	p, err := s.lookup(code)
	if err != nil {
		return PendingView{}, err
	}
	p.state = stateDenied
	s.logf("oauth: request %s denied", p.Code)
	return s.view(p), nil
}

func (s *Server) mountAdmin(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/oauth/pending", func(w http.ResponseWriter, _ *http.Request) {
		list := s.Pending()
		if list == nil {
			list = []PendingView{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"pending": list})
	})
	mux.HandleFunc("POST /admin/oauth/approve", func(w http.ResponseWriter, r *http.Request) {
		var in ApproveRequest
		if !decodeAdmin(w, r, &in) {
			return
		}
		v, err := s.Approve(in)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"request": v})
	})
	mux.HandleFunc("POST /admin/oauth/deny", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Code string `json:"code"`
		}
		if !decodeAdmin(w, r, &in) {
			return
		}
		v, err := s.Deny(in.Code)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"request": v})
	})
	mux.HandleFunc("GET /admin/oauth/grants", func(w http.ResponseWriter, r *http.Request) {
		list, err := s.st.ListOAuthGrants(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"grants": GrantViews(list, time.Now())})
	})
	mux.HandleFunc("POST /admin/oauth/grants/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		g, err := s.st.RevokeOAuthGrant(r.Context(), r.PathValue("id"), "revoked by operator")
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"grant": GrantView{OAuthGrant: g, Status: g.Status(time.Now())}})
	})
}

// GrantViews adds the status to each grant.
func GrantViews(list []store.OAuthGrant, now time.Time) []GrantView {
	out := make([]GrantView, 0, len(list))
	for _, g := range list {
		out = append(out, GrantView{OAuthGrant: g, Status: g.Status(now)})
	}
	return out
}

func decodeAdmin(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxFormBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return false
	}
	return true
}
