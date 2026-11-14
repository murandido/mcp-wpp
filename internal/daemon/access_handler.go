package daemon

import (
	"context"
	"embed"
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/murandido/mcp-wpp/internal/store"
)

// AccessStore is the access-policy surface the operator endpoints need.
// *store.Store satisfies it.
type AccessStore interface {
	AccessMode(ctx context.Context) (string, error)
	SetAccessMode(ctx context.Context, mode string) error
	SetChatAccess(ctx context.Context, jid, state, note string) error
	ListAccess(ctx context.Context, query string, limit int) ([]store.AccessEntry, error)
	ListAccessRequests(ctx context.Context, status string) ([]store.AccessRequest, error)
	DecideAccessRequest(ctx context.Context, id int64, approve bool, jids []string) error
}

//go:embed templates/access.html.tmpl
var accessTemplateFS embed.FS

var accessTmpl = template.Must(template.New("access.html.tmpl").Funcs(template.FuncMap{
	"stateLabel": func(e store.AccessEntry) string {
		switch e.State {
		case store.AccessAllowed:
			return "allowed"
		case store.AccessDenied:
			return "denied"
		}
		if e.Visible {
			return "visible (mode all)"
		}
		return "hidden"
	},
}).ParseFS(accessTemplateFS, "templates/access.html.tmpl"))

// accessHandlers serves the operator's consent workflow: JSON under
// /admin/access (bearer only, used by `wpp-mcp access`) and the /access
// page (session cookie plus CSRF token).
type accessHandlers struct {
	st AccessStore

	csrfMu sync.Mutex
	csrf   map[string]bool
}

func newAccessHandlers(st AccessStore) *accessHandlers {
	return &accessHandlers{st: st, csrf: map[string]bool{}}
}

func (h *accessHandlers) mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/access", h.apiList)
	mux.HandleFunc("POST /admin/access/mode", h.apiMode)
	mux.HandleFunc("POST /admin/access/chat", h.apiChat)
	mux.HandleFunc("GET /admin/access/requests", h.apiRequests)
	mux.HandleFunc("POST /admin/access/requests/{id}", h.apiDecide)

	mux.HandleFunc("GET /access", h.page)
	mux.HandleFunc("POST /access/mode", h.form(func(r *http.Request) error {
		return h.st.SetAccessMode(r.Context(), r.FormValue("mode"))
	}))
	mux.HandleFunc("POST /access/chat", h.form(func(r *http.Request) error {
		return h.st.SetChatAccess(r.Context(), r.FormValue("jid"), formState(r.FormValue("state")), "set on /access")
	}))
	mux.HandleFunc("POST /access/requests/{id}", h.form(func(r *http.Request) error {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			return err
		}
		return h.st.DecideAccessRequest(r.Context(), id, r.FormValue("decision") == "approve", r.Form["jid"])
	}))
}

func formState(v string) string {
	if v == "reset" {
		return store.AccessDefault
	}
	return v
}

// --- JSON API --------------------------------------------------------------

func (h *accessHandlers) apiList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	mode, err := h.st.AccessMode(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	chats, err := h.st.ListAccess(ctx, r.URL.Query().Get("query"), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": mode, "chats": chats})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return false
	}
	return true
}

func (h *accessHandlers) apiMode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode string `json:"mode"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := h.st.SetAccessMode(r.Context(), body.Mode); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"mode": body.Mode})
}

func (h *accessHandlers) apiChat(w http.ResponseWriter, r *http.Request) {
	var body struct {
		JID   string `json:"jid"`
		State string `json:"state"` // allowed, denied or reset
		Note  string `json:"note"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := h.st.SetChatAccess(r.Context(), body.JID, formState(body.State), body.Note); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"jid": body.JID, "state": body.State})
}

func (h *accessHandlers) apiRequests(w http.ResponseWriter, r *http.Request) {
	reqs, err := h.st.ListAccessRequests(r.Context(), r.URL.Query().Get("status"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": reqs})
}

func (h *accessHandlers) apiDecide(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request id"})
		return
	}
	var body struct {
		Approve bool     `json:"approve"`
		JIDs    []string `json:"jids"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := h.st.DecideAccessRequest(r.Context(), id, body.Approve, body.JIDs); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "approved": body.Approve})
}

// --- HTML page ---------------------------------------------------------------

type accessPageData struct {
	CSRFToken string
	Mode      string
	Query     string
	Chats     []store.AccessEntry
	Requests  []store.AccessRequest
	Error     string
}

func (h *accessHandlers) mintCSRF() string {
	h.csrfMu.Lock()
	defer h.csrfMu.Unlock()
	if len(h.csrf) > 64 {
		h.csrf = map[string]bool{}
	}
	t := randomToken()
	h.csrf[t] = true
	return t
}

func (h *accessHandlers) useCSRF(t string) bool {
	h.csrfMu.Lock()
	defer h.csrfMu.Unlock()
	if t == "" || !h.csrf[t] {
		return false
	}
	delete(h.csrf, t)
	return true
}

func (h *accessHandlers) page(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data := accessPageData{CSRFToken: h.mintCSRF(), Query: r.URL.Query().Get("q"), Error: r.URL.Query().Get("error")}
	var err error
	if data.Mode, err = h.st.AccessMode(ctx); err == nil {
		if data.Chats, err = h.st.ListAccess(ctx, data.Query, 300); err == nil {
			data.Requests, err = h.st.ListAccessRequests(ctx, "pending")
		}
	}
	if err != nil {
		http.Error(w, "access store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := accessTmpl.Execute(w, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// form wraps a state-changing form post: CSRF check, action, redirect back.
func (h *accessHandlers) form(action func(*http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || !h.useCSRF(r.FormValue("csrf_token")) {
			http.Error(w, "invalid or missing CSRF token; reload /access", http.StatusForbidden)
			return
		}
		back := "/access"
		if q := strings.TrimSpace(r.FormValue("q")); q != "" {
			back += "?q=" + template.URLQueryEscaper(q)
		}
		if err := action(r); err != nil {
			sep := "?"
			if strings.Contains(back, "?") {
				sep = "&"
			}
			back += sep + "error=" + template.URLQueryEscaper(err.Error())
		}
		http.Redirect(w, r, back, http.StatusSeeOther)
	}
}
