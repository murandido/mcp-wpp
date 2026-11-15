package daemon

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/murandido/mcp-wpp/internal/store"
)

// TokenVerifier checks a client API token. *store.Store satisfies it; it
// returns an error for unknown, revoked and expired tokens alike.
type TokenVerifier interface {
	VerifyAPIToken(ctx context.Context, plain string) (store.APIToken, error)
}

// TokenStore is the token management surface behind /admin/tokens.
// *store.Store satisfies it.
type TokenStore interface {
	TokenVerifier
	CreateAPIToken(ctx context.Context, in store.NewAPIToken) (store.APIToken, string, error)
	ListAPITokens(ctx context.Context) ([]store.APIToken, error)
	RevokeAPIToken(ctx context.Context, ref string) (store.APIToken, error)
}

// AuditLog stores and lists audit entries. *store.Store satisfies it.
type AuditLog interface {
	RecordAudit(ctx context.Context, e store.AuditEntry) error
	ListAudit(ctx context.Context, f store.AuditFilter) ([]store.AuditEntry, error)
}

// tokenView is a token with its status, as the admin API returns it.
type tokenView struct {
	store.APIToken
	Status string `json:"status"`
}

// mountTokenAdmin serves the client token API (bearer only, used by
// `wpp-mcp token`). The plaintext of a new token appears once, in the
// creation response.
func mountTokenAdmin(mux *http.ServeMux, ts TokenStore) {
	mux.HandleFunc("GET /admin/tokens", func(w http.ResponseWriter, r *http.Request) {
		list, err := ts.ListAPITokens(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		now := time.Now()
		out := make([]tokenView, 0, len(list))
		for _, t := range list {
			out = append(out, tokenView{APIToken: t, Status: t.Status(now)})
		}
		writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
	})
	mux.HandleFunc("POST /admin/tokens", func(w http.ResponseWriter, r *http.Request) {
		var in store.NewAPIToken
		if !decodeJSON(w, r, &in) {
			return
		}
		t, plain, err := ts.CreateAPIToken(r.Context(), in)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"token": tokenView{APIToken: t, Status: t.Status(time.Now())}, "secret": plain})
	})
	mux.HandleFunc("POST /admin/tokens/{ref}/revoke", func(w http.ResponseWriter, r *http.Request) {
		t, err := ts.RevokeAPIToken(r.Context(), r.PathValue("ref"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"token": tokenView{APIToken: t, Status: t.Status(time.Now())}})
	})
}

// mountAuditAdmin serves GET /admin/audit?since=RFC3339&actor=&chat=&limit=.
func mountAuditAdmin(mux *http.ServeMux, al AuditLog) {
	mux.HandleFunc("GET /admin/audit", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f := store.AuditFilter{Actor: q.Get("actor"), ChatJID: q.Get("chat")}
		if v := q.Get("since"); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "since must be RFC 3339"})
				return
			}
			f.Since = t
		}
		f.Limit, _ = strconv.Atoi(q.Get("limit"))
		entries, err := al.ListAudit(r.Context(), f)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
	})
}
