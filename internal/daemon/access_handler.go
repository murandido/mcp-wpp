package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"

	"github.com/murandido/mcp-wpp/internal/store"
)

// AccessStore is the access-policy surface the operator endpoints need.
// *store.Store satisfies it.
type AccessStore interface {
	AccessMode(ctx context.Context) (string, error)
	SetAccessMode(ctx context.Context, mode string) error
	SetChatAccess(ctx context.Context, jid, state, note string) error
	SetChatSendPolicy(ctx context.Context, jid, policy string) error
	SetChatSendWindow(ctx context.Context, jid, window string) error
	ListAccess(ctx context.Context, query string, limit int) ([]store.AccessEntry, error)
	ListAccessPage(ctx context.Context, opts store.AccessListOptions) (store.AccessListPage, error)
	ChatsExist(ctx context.Context, jids []string) (map[string]bool, error)
	ListAccessRequests(ctx context.Context, status string) ([]store.AccessRequest, error)
	DecideAccessRequest(ctx context.Context, id int64, approve bool, jids []string) error
	GetChatNotes(ctx context.Context, jid string) (store.ChatNotes, error)
	ChatNotesHistory(ctx context.Context, jid string) ([]store.ChatNotesVersion, error)
	RevertChatNotes(ctx context.Context, jid string, version int) (store.ChatNotes, error)
	ClearChatNotes(ctx context.Context, jid string) error
	NotesVersions(ctx context.Context) (map[string]int, error)
}

// accessHandlers serves the operator's consent workflow: JSON under
// /admin/access (bearer only, used by `wpp-mcp access`) and the /access
// page (session cookie plus CSRF token).
type accessHandlers struct {
	st AccessStore
	// defaultSend reports the daemon's default send policy for chats
	// without one (nil when no write-mode MCP server is attached).
	defaultSend func() string

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
	mux.HandleFunc("POST /admin/access/send", h.apiSend)
	mux.HandleFunc("POST /admin/access/window", h.apiWindow)
	mux.HandleFunc("GET /admin/access/requests", h.apiRequests)
	mux.HandleFunc("POST /admin/access/requests/{id}", h.apiDecide)

	mux.HandleFunc("GET /access", h.page)
	mux.HandleFunc("GET /access/mode", h.modeConfirm)
	mux.HandleFunc("POST /access/mode", h.form(plain(func(r *http.Request) error {
		// The page asks first (GET /access/mode); a post without the
		// confirmation changes nothing.
		if r.FormValue("confirm") != "yes" {
			return errors.New("confirm the mode change on its confirmation page")
		}
		return h.st.SetAccessMode(r.Context(), r.FormValue("mode"))
	})))
	mux.HandleFunc("POST /access/bulk/review", h.bulkReview)
	mux.HandleFunc("POST /access/bulk", h.form(h.bulkApply))
	mux.HandleFunc("POST /access/chat", h.form(plain(func(r *http.Request) error {
		return h.st.SetChatAccess(r.Context(), r.FormValue("jid"), formState(r.FormValue("state")), "set on /access")
	})))
	mux.HandleFunc("POST /access/send", h.form(plain(func(r *http.Request) error {
		return h.st.SetChatSendPolicy(r.Context(), r.FormValue("jid"), r.FormValue("send"))
	})))
	mux.HandleFunc("POST /access/requests/{id}", h.form(plain(func(r *http.Request) error {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			return err
		}
		return h.st.DecideAccessRequest(r.Context(), id, r.FormValue("decision") == "approve", r.Form["jid"])
	})))
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
	writeJSON(w, http.StatusOK, map[string]any{"mode": mode, "chats": chats, "default_send": h.defaultSendPolicy()})
}

func (h *accessHandlers) defaultSendPolicy() string {
	if h.defaultSend == nil {
		return ""
	}
	return h.defaultSend()
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

// apiSend sets a chat's send policy: none, confirm, direct, or reset.
func (h *accessHandlers) apiSend(w http.ResponseWriter, r *http.Request) {
	var body struct {
		JID  string `json:"jid"`
		Send string `json:"send"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := h.st.SetChatSendPolicy(r.Context(), body.JID, body.Send); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"jid": body.JID, "send": body.Send})
}

// apiWindow sets a chat's send window ("08:00-22:00") or clears it ("off").
func (h *accessHandlers) apiWindow(w http.ResponseWriter, r *http.Request) {
	var body struct {
		JID    string `json:"jid"`
		Window string `json:"window"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := h.st.SetChatSendWindow(r.Context(), body.JID, body.Window); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"jid": body.JID, "window": body.Window})
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
