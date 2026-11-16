package daemon

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/murandido/mcp-wpp/internal/store"
)

// The /access page: the operator's consent workflow in a browser. It is
// authenticated by the session cookie (classBrowser), every state change
// is a POST with a single-use CSRF token, and everything works without
// JavaScript; the one inline script (select all) carries the response's
// CSP nonce. Changes go through the same AccessStore calls as the CLI's
// /admin/access API, and auditAdmin records them the same way.

//go:embed templates/access.html.tmpl templates/access_confirm.html.tmpl templates/access_head.html.tmpl templates/outbox.html.tmpl
var accessTemplateFS embed.FS

var accessFuncs = template.FuncMap{
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
}

var (
	accessTmpl        = template.Must(template.New("access.html.tmpl").Funcs(accessFuncs).ParseFS(accessTemplateFS, "templates/access.html.tmpl", "templates/access_head.html.tmpl"))
	accessConfirmTmpl = template.Must(template.New("access_confirm.html.tmpl").Funcs(accessFuncs).ParseFS(accessTemplateFS, "templates/access_confirm.html.tmpl", "templates/access_head.html.tmpl"))
)

const (
	// accessPageSize is how many chats one page lists.
	accessPageSize = 50
	// maxAccessPage bounds the page parameter.
	maxAccessPage = 1000
	// maxAccessQuery bounds the search text, in characters.
	maxAccessQuery = 100
	// maxBulkChats is the most chats one bulk action may change.
	maxBulkChats = 100
	// maxAccessForm bounds a form body.
	maxAccessForm = 64 << 10
	// maxShownError bounds the error text echoed from the redirect.
	maxShownError = 300
)

var accessFilterLabels = []struct{ Value, Label string }{
	{store.AccessFilterAll, "All"},
	{store.AccessFilterAllowed, "Allowed"},
	{store.AccessFilterDenied, "Denied"},
	{store.AccessFilterPending, "Pending requests"},
	{store.AccessFilterGroups, "Groups"},
	{store.AccessFilterDirect, "Direct chats"},
}

// listParams is the list state the page keeps across links and form posts.
type listParams struct {
	Query  string
	Filter string
	Page   int
}

// parseListParams validates the search, filter and page from a query
// string or form; anything out of range falls back to the default.
func parseListParams(get func(string) string) listParams {
	p := listParams{Query: truncateRunes(strings.TrimSpace(get("q")), maxAccessQuery), Filter: get("filter"), Page: 1}
	if !store.ValidAccessFilter(p.Filter) {
		p.Filter = store.AccessFilterAll
	}
	if n, err := strconv.Atoi(get("page")); err == nil && n >= 1 && n <= maxAccessPage {
		p.Page = n
	}
	return p
}

func (p listParams) values() url.Values {
	v := url.Values{}
	if p.Query != "" {
		v.Set("q", p.Query)
	}
	if p.Filter != store.AccessFilterAll {
		v.Set("filter", p.Filter)
	}
	if p.Page > 1 {
		v.Set("page", strconv.Itoa(p.Page))
	}
	return v
}

// url returns /access with these params plus extra (key, value pairs).
func (p listParams) url(extra ...string) string {
	v := p.values()
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	if len(v) == 0 {
		return "/access"
	}
	return "/access?" + v.Encode()
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

type filterLink struct {
	Label  string
	URL    string
	Active bool
}

type accessView struct {
	Nonce       string
	CSRFToken   string
	Mode        string
	DefaultSend string
	List        listParams
	Filters     []filterLink
	Chats       []store.AccessEntry
	Total       int
	From, To    int
	PrevURL     string
	NextURL     string
	ClearURL    string
	Requests    []store.AccessRequest
	Error       string
	Notice      string
	MaxBulk     int
}

// noticeText maps the fixed codes a redirect carries to messages, so the
// URL cannot put arbitrary text on the page.
func noticeText(code, n string) string {
	count, err := strconv.Atoi(n)
	if err != nil || count < 0 || count > maxBulkChats {
		return ""
	}
	switch code {
	case "allowed":
		return fmt.Sprintf("Allowed %d chat(s).", count)
	case "reset":
		return fmt.Sprintf("Reset %d chat(s) to the mode's default.", count)
	}
	return ""
}

// setPageHeaders marks an operator page uncacheable and restricts it to
// its own nonce-tagged style and script.
func setPageHeaders(w http.ResponseWriter, nonce string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+nonce+"'; script-src 'nonce-"+nonce+"'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
}

func (h *accessHandlers) page(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	list := parseListParams(q.Get)
	v := accessView{
		Nonce:       randomToken()[:32],
		CSRFToken:   h.mintCSRF(),
		DefaultSend: h.defaultSendPolicy(),
		Error:       truncateRunes(q.Get("error"), maxShownError),
		Notice:      noticeText(q.Get("done"), q.Get("n")),
		MaxBulk:     maxBulkChats,
	}
	var err error
	if v.Mode, err = h.st.AccessMode(ctx); err != nil {
		http.Error(w, "access store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if v.Requests, err = h.st.ListAccessRequests(ctx, "pending"); err != nil {
		http.Error(w, "access store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	pg, err := h.st.ListAccessPage(ctx, store.AccessListOptions{Query: list.Query, Filter: list.Filter, Offset: (list.Page - 1) * accessPageSize, Limit: accessPageSize})
	if err == nil && len(pg.Chats) == 0 && list.Page > 1 && pg.Total > 0 {
		// Past the end (the list shrank after an action): show the last page.
		list.Page = (pg.Total + accessPageSize - 1) / accessPageSize
		pg, err = h.st.ListAccessPage(ctx, store.AccessListOptions{Query: list.Query, Filter: list.Filter, Offset: (list.Page - 1) * accessPageSize, Limit: accessPageSize})
	}
	if err != nil {
		http.Error(w, "access store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	v.List, v.Chats, v.Total = list, pg.Chats, pg.Total
	if len(pg.Chats) > 0 {
		v.From = (list.Page-1)*accessPageSize + 1
		v.To = v.From + len(pg.Chats) - 1
	}
	if list.Page > 1 {
		prev := list
		prev.Page--
		v.PrevURL = prev.url()
	}
	if v.To < v.Total && list.Page < maxAccessPage {
		next := list
		next.Page++
		v.NextURL = next.url()
	}
	for _, f := range accessFilterLabels {
		l := listParams{Query: list.Query, Filter: f.Value, Page: 1}
		v.Filters = append(v.Filters, filterLink{Label: f.Label, URL: l.url(), Active: f.Value == list.Filter})
	}
	v.ClearURL = listParams{Filter: list.Filter, Page: 1}.url()

	setPageHeaders(w, v.Nonce)
	if err := accessTmpl.Execute(w, v); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// --- Confirmation pages ------------------------------------------------------

type accessConfirmView struct {
	Nonce     string
	CSRFToken string
	List      listParams
	BackURL   string

	// Mode change.
	Mode, NewMode       string
	Allowed, Denied     int
	TotalChats, Visible int

	// Bulk action.
	State   string // "allowed" or "reset"
	Chats   []store.AccessEntry
	Missing int
}

func (h *accessHandlers) renderConfirm(w http.ResponseWriter, v accessConfirmView) {
	v.Nonce = randomToken()[:32]
	v.CSRFToken = h.mintCSRF()
	v.BackURL = v.List.url()
	setPageHeaders(w, v.Nonce)
	if err := accessConfirmTmpl.Execute(w, v); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// modeConfirm (GET /access/mode?mode=...) explains what switching the
// access mode does before the operator posts it. It changes nothing.
func (h *accessHandlers) modeConfirm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	list := parseListParams(r.URL.Query().Get)
	newMode := r.URL.Query().Get("mode")
	cur, err := h.st.AccessMode(ctx)
	if err != nil {
		http.Error(w, "access store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if (newMode != store.AccessAllowlist && newMode != store.AccessAll) || newMode == cur {
		http.Redirect(w, r, list.url(), http.StatusSeeOther)
		return
	}
	v := accessConfirmView{List: list, Mode: cur, NewMode: newMode}
	for _, c := range []struct {
		filter string
		n      *int
	}{{store.AccessFilterAll, &v.TotalChats}, {store.AccessFilterAllowed, &v.Allowed}, {store.AccessFilterDenied, &v.Denied}} {
		pg, err := h.st.ListAccessPage(ctx, store.AccessListOptions{Filter: c.filter, Limit: 1})
		if err != nil {
			http.Error(w, "access store: "+err.Error(), http.StatusInternalServerError)
			return
		}
		*c.n = pg.Total
	}
	v.Visible = v.Allowed
	if newMode == store.AccessAll {
		v.Visible = v.TotalChats - v.Denied
	}
	h.renderConfirm(w, v)
}

// bulkSelection validates the chats and state of a bulk form: field names
// the chats ("chat" from the list, "jid" from the confirmation page).
func (h *accessHandlers) bulkSelection(r *http.Request, field string) (jids []string, state string, err error) {
	state = r.FormValue("state")
	if state != store.AccessAllowed && state != "reset" {
		return nil, "", errors.New("bulk action must be allow or reset")
	}
	jids = nonEmpty(r.Form[field])
	switch {
	case len(jids) == 0:
		return nil, "", errors.New("select at least one chat")
	case len(jids) > maxBulkChats:
		return nil, "", fmt.Errorf("select at most %d chats at a time (got %d)", maxBulkChats, len(jids))
	}
	exist, err := h.st.ChatsExist(r.Context(), jids)
	if err != nil {
		return nil, "", err
	}
	kept := jids[:0]
	for _, j := range jids {
		if exist[j] {
			kept = append(kept, j)
		}
	}
	if len(kept) == 0 {
		return nil, "", errors.New("none of the selected chats is cached")
	}
	return kept, state, nil
}

// bulkReview (POST /access/bulk/review) shows the selected chats and asks
// for confirmation. It consumes a CSRF token but changes nothing.
func (h *accessHandlers) bulkReview(w http.ResponseWriter, r *http.Request) {
	if !h.checkForm(w, r) {
		return
	}
	list := parseListParams(r.FormValue)
	jids, state, err := h.bulkSelection(r, "chat")
	if err != nil {
		http.Redirect(w, r, list.url("error", err.Error()), http.StatusSeeOther)
		return
	}
	all, err := h.st.ListAccess(r.Context(), "", 1<<30)
	if err != nil {
		http.Error(w, "access store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	want := map[string]bool{}
	for _, j := range jids {
		want[j] = true
	}
	v := accessConfirmView{List: list, State: state}
	for _, e := range all {
		if want[e.JID] {
			v.Chats = append(v.Chats, e)
		}
	}
	v.Missing = len(r.Form["chat"]) - len(v.Chats)
	h.renderConfirm(w, v)
}

// bulkApply (POST /access/bulk) applies a confirmed bulk action. auditAdmin
// records one entry per chat, as if each had been changed on its own.
func (h *accessHandlers) bulkApply(r *http.Request) (formDone, error) {
	if r.FormValue("confirm") != "yes" {
		return formDone{}, errors.New("review the selection before applying it")
	}
	jids, state, err := h.bulkSelection(r, "jid")
	if err != nil {
		return formDone{}, err
	}
	for i, jid := range jids {
		if err := h.st.SetChatAccess(r.Context(), jid, formState(state), "bulk on /access"); err != nil {
			return formDone{}, fmt.Errorf("changed %d of %d chats, then: %w", i, len(jids), err)
		}
	}
	return formDone{code: state, n: len(jids)}, nil
}

// --- CSRF and form posts -----------------------------------------------------

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

// checkForm parses a bounded form body and consumes its CSRF token,
// answering 403 when it is missing or already used.
func (h *accessHandlers) checkForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxAccessForm)
	if err := r.ParseForm(); err != nil || !h.useCSRF(r.FormValue("csrf_token")) {
		http.Error(w, "invalid or missing CSRF token; reload /access", http.StatusForbidden)
		return false
	}
	return true
}

// formDone is what a successful form post reports back to the list: a
// fixed code and a count (see noticeText), or nothing.
type formDone struct {
	code string
	n    int
}

// plain adapts an action that reports nothing on success.
func plain(f func(*http.Request) error) func(*http.Request) (formDone, error) {
	return func(r *http.Request) (formDone, error) { return formDone{}, f(r) }
}

// form wraps a state-changing form post: CSRF check, action, redirect back
// to the list the operator was on.
func (h *accessHandlers) form(action func(*http.Request) (formDone, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.checkForm(w, r) {
			return
		}
		list := parseListParams(r.FormValue)
		done, err := action(r)
		back := list.url()
		switch {
		case err != nil:
			back = list.url("error", truncateRunes(err.Error(), maxShownError))
		case done.code != "":
			back = list.url("done", done.code, "n", strconv.Itoa(done.n))
		}
		http.Redirect(w, r, back, http.StatusSeeOther) // always the local /access page; only the query is user text
	}
}
