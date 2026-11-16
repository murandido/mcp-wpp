package daemon

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/murandido/mcp-wpp/internal/store"
)

// Chat notes for the operator: JSON under /admin/notes (bearer only, used by
// `wpp-mcp notes`) and the /notes page (session cookie plus CSRF token).
// The operator sees every chat's notes; MCP clients only see their own
// chats' through the scoped store.

type notesView struct {
	Nonce     string
	CSRFToken string
	JID       string
	Notes     store.ChatNotes
	History   []store.ChatNotesVersion
	Error     string
	Notice    string
}

func (h *accessHandlers) mountNotes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/notes", h.apiNotes)
	mux.HandleFunc("POST /admin/notes/revert", h.apiNotesRevert)
	mux.HandleFunc("POST /admin/notes/clear", h.apiNotesClear)

	mux.HandleFunc("GET /notes", h.notesPage)
	mux.HandleFunc("POST /notes/revert", h.notesForm(func(r *http.Request) (string, error) {
		v, err := strconv.Atoi(r.FormValue("version"))
		if err != nil {
			return "", errors.New("invalid version")
		}
		_, err = h.st.RevertChatNotes(r.Context(), r.FormValue("jid"), v)
		return "reverted", err
	}))
	mux.HandleFunc("POST /notes/clear", h.notesForm(func(r *http.Request) (string, error) {
		if r.FormValue("confirm") != "yes" {
			return "", errors.New("tick the confirmation to clear the notes")
		}
		return "cleared", h.st.ClearChatNotes(r.Context(), r.FormValue("jid"))
	}))
}

func (h *accessHandlers) apiNotes(w http.ResponseWriter, r *http.Request) {
	jid := strings.TrimSpace(r.URL.Query().Get("jid"))
	if jid == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "jid is required"})
		return
	}
	n, err := h.st.GetChatNotes(r.Context(), jid)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	hist, err := h.st.ChatNotesHistory(r.Context(), jid)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"notes": n, "history": hist})
}

func (h *accessHandlers) apiNotesRevert(w http.ResponseWriter, r *http.Request) {
	var body struct {
		JID     string `json:"jid"`
		Version int    `json:"version"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	n, err := h.st.RevertChatNotes(r.Context(), body.JID, body.Version)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, n)
}

func (h *accessHandlers) apiNotesClear(w http.ResponseWriter, r *http.Request) {
	var body struct {
		JID string `json:"jid"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := h.st.ClearChatNotes(r.Context(), body.JID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"jid": body.JID, "status": "cleared"})
}

// notesURL is the local /notes page for jid with optional key/value pairs.
func notesURL(jid string, kv ...string) string {
	v := url.Values{"jid": {jid}}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return "/notes?" + v.Encode()
}

func (h *accessHandlers) notesForm(action func(*http.Request) (string, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.checkForm(w, r) {
			return
		}
		jid := truncateRunes(strings.TrimSpace(r.FormValue("jid")), 200)
		done, err := action(r)
		back := notesURL(jid, "done", done)
		if err != nil {
			back = notesURL(jid, "error", truncateRunes(err.Error(), maxShownError))
		}
		http.Redirect(w, r, back, http.StatusSeeOther) // always the local /notes page; only the query is user text
	}
}

func (h *accessHandlers) notesPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	v := notesView{
		Nonce:     randomToken()[:32],
		CSRFToken: h.mintCSRF(),
		JID:       truncateRunes(strings.TrimSpace(q.Get("jid")), 200),
		Error:     truncateRunes(q.Get("error"), maxShownError),
	}
	switch q.Get("done") {
	case "reverted":
		v.Notice = "Reverted: the selected version is current again."
	case "cleared":
		v.Notice = "Notes cleared."
	}
	if v.JID == "" {
		http.Error(w, "jid is required", http.StatusBadRequest)
		return
	}
	var err error
	if v.Notes, err = h.st.GetChatNotes(r.Context(), v.JID); err != nil {
		http.Error(w, "notes store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if v.History, err = h.st.ChatNotesHistory(r.Context(), v.JID); err != nil {
		http.Error(w, "notes store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	setPageHeaders(w, v.Nonce)
	if err := notesTmpl.Execute(w, v); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}
