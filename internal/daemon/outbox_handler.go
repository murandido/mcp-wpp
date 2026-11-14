package daemon

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"sync"

	"github.com/murandido/mcp-wpp/internal/store"
)

// Outbox is the proposal queue the operator approves. *mcp.Server
// implements it: approving runs the proposed tool.
type Outbox interface {
	ListProposals(ctx context.Context, status string) ([]store.Proposal, error)
	ApproveProposal(ctx context.Context, id int64) (store.Proposal, error)
	RejectProposal(ctx context.Context, id int64) error
}

var outboxTmpl = template.Must(template.ParseFS(accessTemplateFS, "templates/outbox.html.tmpl"))

type outboxHandlers struct {
	ob     Outbox
	csrfMu sync.Mutex
	csrf   map[string]bool
}

func (h *outboxHandlers) mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/outbox", func(w http.ResponseWriter, r *http.Request) {
		ps, err := h.ob.ListProposals(r.Context(), r.URL.Query().Get("status"))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"proposals": ps})
	})
	mux.HandleFunc("POST /admin/outbox/{id}/{decision}", func(w http.ResponseWriter, r *http.Request) {
		p, err := h.decide(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, p)
	})
	mux.HandleFunc("GET /outbox", func(w http.ResponseWriter, r *http.Request) {
		pending, err := h.ob.ListProposals(r.Context(), "pending")
		if err == nil {
			var recent []store.Proposal
			if recent, err = h.ob.ListProposals(r.Context(), ""); err == nil {
				if len(recent) > 20 {
					recent = recent[:20]
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				_ = outboxTmpl.Execute(w, map[string]any{
					"CSRFToken": h.mint(), "Pending": pending, "Recent": recent, "Error": r.URL.Query().Get("error"),
				})
				return
			}
		}
		http.Error(w, "outbox: "+err.Error(), http.StatusInternalServerError)
	})
	mux.HandleFunc("POST /outbox/{id}/{decision}", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || !h.use(r.FormValue("csrf_token")) {
			http.Error(w, "invalid or missing CSRF token; reload /outbox", http.StatusForbidden)
			return
		}
		back := "/outbox"
		if _, err := h.decide(r); err != nil {
			back += "?error=" + template.URLQueryEscaper(err.Error())
		}
		http.Redirect(w, r, back, http.StatusSeeOther) //nolint:gosec // G710: always the local /outbox page; only the query is user text
	})
}

func (h *outboxHandlers) decide(r *http.Request) (any, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return nil, err
	}
	switch r.PathValue("decision") {
	case "approve":
		return h.ob.ApproveProposal(r.Context(), id)
	case "reject":
		return map[string]any{"id": id, "status": "rejected"}, h.ob.RejectProposal(r.Context(), id)
	}
	return nil, errors.New("decision must be approve or reject")
}

func (h *outboxHandlers) mint() string {
	h.csrfMu.Lock()
	defer h.csrfMu.Unlock()
	if h.csrf == nil || len(h.csrf) > 64 {
		h.csrf = map[string]bool{}
	}
	t := randomToken()
	h.csrf[t] = true
	return t
}

func (h *outboxHandlers) use(t string) bool {
	h.csrfMu.Lock()
	defer h.csrfMu.Unlock()
	if t == "" || !h.csrf[t] {
		return false
	}
	delete(h.csrf, t)
	return true
}
