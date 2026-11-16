package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/murandido/mcp-wpp/internal/auth"
	"github.com/murandido/mcp-wpp/internal/store"
)

// Operator audit. auditAdmin wraps the mux and records every state-changing
// request to the admin API and the operator pages (access decisions,
// outbox approvals, token changes, pairing, login links) after it ran: the
// route, the chat it named, a few whitelisted fields, the actor and whether
// it succeeded. MCP traffic is audited per tool call in internal/mcp.

// auditChatFields name the chat a request acts on. A form that repeats the
// field (a bulk action on /access, or approving several matches of a
// request) gets one entry per chat, up to maxAuditChats.
var auditChatFields = []string{"jid", "chat_jid"}

// auditDetailFields are recorded verbatim. Anything else in a request
// (phone numbers, message text, token secrets) is never read into the log.
var auditDetailFields = map[string]bool{
	"mode": true, "state": true, "decision": true, "approve": true,
	"name": true, "scopes": true, "chats": true, "expires_at": true,
	"code": true, "days": true, "send": true,
}

// maxAuditChats bounds the entries one request can produce. The /access
// bulk form accepts fewer chats than this.
const maxAuditChats = 500

// maxAuditPeek bounds how much of a request body is inspected.
const maxAuditPeek = 64 << 10

var patternWildcard = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)(\.\.\.)?\}`)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func auditAdmin(next http.Handler, al AuditLog) http.Handler {
	if al == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if isMCPPath(r.URL.Path) || classify(r.URL.Path) == classPublic {
			next.ServeHTTP(w, r)
			return
		}
		fields := peekFields(r)
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		notes := &auditNotes{}
		r = r.WithContext(context.WithValue(r.Context(), auditNotesKey{}, notes))
		next.ServeHTTP(rec, r)
		if r.Pattern == "" {
			return // no route matched
		}
		id := auth.Caller(r.Context())
		e := store.AuditEntry{
			At:       start.UTC(),
			Actor:    id.Actor(),
			TokenID:  id.TokenID,
			Kind:     store.AuditAdmin,
			Action:   r.Pattern,
			Duration: time.Since(start).Milliseconds(),
			Outcome:  store.OutcomeOK,
		}
		var chats []string
		for _, k := range auditChatFields {
			if vs := nonEmpty(fields[k]); len(vs) > 0 {
				chats = vs
				break
			}
		}
		if len(chats) > maxAuditChats {
			chats = chats[:maxAuditChats]
		}
		var detail []string
		for _, m := range patternWildcard.FindAllStringSubmatch(r.Pattern, -1) {
			if v := r.PathValue(m[1]); v != "" {
				detail = append(detail, m[1]+"="+v)
			}
		}
		keys := make([]string, 0, len(fields))
		for k := range fields {
			if auditDetailFields[k] {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			detail = append(detail, k+"="+strings.Join(fields[k], ","))
		}
		if len(chats) > 1 {
			detail = append(detail, fmt.Sprintf("batch=%d", len(chats)))
		}
		detail = append(detail, notes.list...)
		if id.Via == "session" {
			detail = append(detail, "via=browser")
		}
		e.Detail = strings.Join(detail, " ")
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		// Page forms redirect back with ?error=... when they fail.
		if status >= 400 || (status >= 300 && status < 400 && strings.Contains(rec.Header().Get("Location"), "error=")) {
			e.Outcome = store.OutcomeError
		}
		ctx := context.WithoutCancel(r.Context())
		if len(chats) == 0 {
			_ = al.RecordAudit(ctx, e)
			return
		}
		for _, jid := range chats {
			e.ChatJID = jid
			_ = al.RecordAudit(ctx, e)
		}
	})
}

// nonEmpty returns the distinct non-empty values of vs, in order.
func nonEmpty(vs []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range vs {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// auditNotes collects extra detail a handler adds to its own audit entry
// (addAuditDetail), such as who created an approved proposal.
type auditNotes struct{ list []string }

type auditNotesKey struct{}

// addAuditDetail appends a key=value note to the audit entry of the current
// operator request. Only fixed keys and non-personal values belong here
// (never message text). It does nothing outside auditAdmin.
func addAuditDetail(ctx context.Context, kv string) {
	if n, ok := ctx.Value(auditNotesKey{}).(*auditNotes); ok {
		n.list = append(n.list, kv)
	}
}

// peekFields reads the request's JSON or form fields without consuming the
// body for the handler.
func peekFields(r *http.Request) url.Values {
	out := url.Values{}
	if r.Body == nil || r.Body == http.NoBody {
		return out
	}
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/json" && ct != "application/x-www-form-urlencoded" {
		return out
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, maxAuditPeek))
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(buf), r.Body), r.Body}
	if err != nil {
		return out
	}
	if ct == "application/x-www-form-urlencoded" {
		if v, err := url.ParseQuery(string(buf)); err == nil {
			return v
		}
		return out
	}
	var m map[string]any
	if json.Unmarshal(buf, &m) != nil {
		return out
	}
	for k, v := range m {
		switch x := v.(type) {
		case []any:
			for _, i := range x {
				out.Add(k, fmt.Sprint(i))
			}
		case nil:
		default:
			out.Add(k, fmt.Sprint(x))
		}
	}
	return out
}
