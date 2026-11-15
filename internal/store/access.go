package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// Per-chat consent.
//
// The cache stores every chat, but MCP reads go through a scoped Store
// (Scoped) whose queries only see chats the operator authorised:
//
//   - mode "allowlist" (default): only chats with state 'allowed'.
//   - mode "all": every chat except those with state 'denied'.
//
// The policy lives in messages.db so the CLI, the /access page and the MCP
// server always agree, and it is enforced in SQL (accessFilter) so paging
// and limits stay correct. A chat outside the policy is indistinguishable
// from a chat that does not exist.

const accessSchema = `
CREATE TABLE IF NOT EXISTS access_settings (
	id   INTEGER PRIMARY KEY CHECK (id = 1),
	mode TEXT NOT NULL CHECK (mode IN ('allowlist', 'all'))
);
INSERT OR IGNORE INTO access_settings (id, mode) VALUES (1, 'allowlist');
CREATE TABLE IF NOT EXISTS chat_access (
	jid        TEXT PRIMARY KEY,
	state      TEXT NOT NULL CHECK (state IN ('allowed', 'denied')),
	decided_at TIMESTAMP NOT NULL,
	note       TEXT
);
CREATE TABLE IF NOT EXISTS access_requests (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	query        TEXT NOT NULL,
	reason       TEXT,
	matched_jids TEXT NOT NULL,
	status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
	created_at   TIMESTAMP NOT NULL,
	decided_at   TIMESTAMP
);
`

// Access modes.
const (
	AccessAllowlist = "allowlist"
	AccessAll       = "all"
)

// Access states for a single chat. AccessDefault means no explicit decision.
const (
	AccessAllowed = "allowed"
	AccessDenied  = "denied"
	AccessDefault = ""
)

// maxPendingRequests bounds the request queue so a looping or injected model
// cannot flood the operator.
const maxPendingRequests = 20

// ErrNotFound is returned for chats and messages that do not exist or that
// the access policy hides. The two cases are deliberately identical.
var ErrNotFound = errors.New("not found")

// accessFilter returns a SQL boolean expression that is true when the chat
// JID in column col is visible under the current policy. It takes no
// arguments, so callers can splice it into any WHERE clause.
func accessFilter(col string) string {
	return fmt.Sprintf(`(%[1]s IN (SELECT jid FROM chat_access WHERE state = 'allowed')
		OR ((SELECT mode FROM access_settings WHERE id = 1) = 'all'
		    AND %[1]s NOT IN (SELECT jid FROM chat_access WHERE state = 'denied')))`, col)
}

// Scoped returns a view of the store whose read queries are limited to the
// chats the access policy allows. It shares the underlying connections. The
// MCP server must read through a scoped store; ingestion and internal
// bookkeeping use the unscoped one.
func (s *Store) Scoped() *Store {
	c := *s
	c.scoped = true
	return &c
}

// IsScoped reports whether this view applies the access policy.
func (s *Store) IsScoped() bool { return s.scoped }

// scopeClause returns " AND <filter>" for scoped views and "" otherwise.
func (s *Store) scopeClause(col string) string {
	if !s.scoped {
		return ""
	}
	return " AND " + accessFilter(col) + s.tokenFilter(col)
}

// ChatAllowed reports whether jid is visible under the access policy and,
// on a view narrowed by ScopedTo, the token's chat set.
func (s *Store) ChatAllowed(ctx context.Context, jid string) (bool, error) {
	if jid == "" || !s.tokenAllows(jid) {
		return false, nil
	}
	var ok bool
	err := s.db.QueryRowContext(ctx, "SELECT "+accessFilter("?"), jid, jid).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check chat access: %w", err)
	}
	return ok, nil
}

// AccessMode returns "allowlist" or "all".
func (s *Store) AccessMode(ctx context.Context) (string, error) {
	var mode string
	if err := s.db.QueryRowContext(ctx, "SELECT mode FROM access_settings WHERE id = 1").Scan(&mode); err != nil {
		return "", fmt.Errorf("read access mode: %w", err)
	}
	return mode, nil
}

// SetAccessMode switches between "allowlist" and "all".
func (s *Store) SetAccessMode(ctx context.Context, mode string) error {
	if mode != AccessAllowlist && mode != AccessAll {
		return fmt.Errorf("access mode must be %q or %q", AccessAllowlist, AccessAll)
	}
	_, err := s.db.ExecContext(ctx, "UPDATE access_settings SET mode = ? WHERE id = 1", mode)
	return err
}

// SetChatAccess records an explicit decision for jid. state AccessDefault
// clears it, returning the chat to the mode's default.
func (s *Store) SetChatAccess(ctx context.Context, jid, state, note string) error {
	jid = strings.TrimSpace(jid)
	if jid == "" {
		return errors.New("chat JID is required")
	}
	switch state {
	case AccessDefault:
		_, err := s.db.ExecContext(ctx, "DELETE FROM chat_access WHERE jid = ?", jid)
		return err
	case AccessAllowed, AccessDenied:
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO chat_access (jid, state, decided_at, note) VALUES (?, ?, ?, ?)
			ON CONFLICT(jid) DO UPDATE SET state = excluded.state, decided_at = excluded.decided_at, note = excluded.note`,
			jid, state, time.Now().UTC(), nullIfEmpty(note))
		return err
	default:
		return fmt.Errorf("unknown access state %q", state)
	}
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// AccessEntry is one chat as the operator sees it.
type AccessEntry struct {
	JID             string    `json:"jid"`
	Name            string    `json:"name"`
	IsGroup         bool      `json:"is_group"`
	LastMessageTime time.Time `json:"last_message_time"`
	State           string    `json:"state"`   // allowed, denied or "" (default)
	Visible         bool      `json:"visible"` // effective result under the current mode
}

// ListAccess lists cached chats with their access state, most recent first.
// query filters by name or JID (accent- and case-insensitive).
func (s *Store) ListAccess(ctx context.Context, query string, limit int) ([]AccessEntry, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.jid, COALESCE(c.name, ''), c.last_message_time, COALESCE(a.state, ''), `+accessFilter("c.jid")+`
		FROM chats c LEFT JOIN chat_access a ON a.jid = c.jid
		ORDER BY c.last_message_time DESC`)
	if err != nil {
		return nil, fmt.Errorf("list access: %w", err)
	}
	defer rows.Close()
	needle := foldText(query)
	var out []AccessEntry
	for rows.Next() {
		var e AccessEntry
		var ts sql.NullTime
		if err := rows.Scan(&e.JID, &e.Name, &ts, &e.State, &e.Visible); err != nil {
			return nil, err
		}
		raw := e.Name
		e.Name = s.displayName(ctx, e.JID, raw)
		if needle != "" && !strings.Contains(foldText(e.Name), needle) && !strings.Contains(foldText(raw), needle) && !strings.Contains(e.JID, needle) {
			continue
		}
		e.LastMessageTime = ts.Time
		e.IsGroup = strings.HasSuffix(e.JID, "@g.us")
		out = append(out, e)
		if len(out) >= limit {
			break
		}
	}
	return out, rows.Err()
}

// ResolveChats returns chats whose JID equals ref or whose name contains it
// (accent- and case-insensitive). Used by the operator CLI and by access
// requests.
func (s *Store) ResolveChats(ctx context.Context, ref string, limit int) ([]AccessEntry, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("empty chat reference")
	}
	all, err := s.ListAccess(ctx, "", 100000)
	if err != nil {
		return nil, err
	}
	for _, e := range all {
		if e.JID == ref {
			return []AccessEntry{e}, nil
		}
	}
	needle := foldText(ref)
	var out []AccessEntry
	for _, e := range all {
		if strings.Contains(foldText(e.Name), needle) || strings.HasPrefix(e.JID, ref) {
			out = append(out, e)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

// foldText lowercases and strips diacritics: "João" → "joao".
func foldText(s string) string {
	t := transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)
	out, _, err := transform.String(t, strings.ToLower(strings.TrimSpace(s)))
	if err != nil {
		return strings.ToLower(s)
	}
	return out
}

// AccessRequest is a model's request to see a chat.
type AccessRequest struct {
	ID          int64           `json:"id"`
	Query       string          `json:"query"`
	Reason      string          `json:"reason,omitempty"`
	Matches     []AccessEntry   `json:"matches"`
	Status      string          `json:"status"`
	CreatedAt   time.Time       `json:"created_at"`
	DecidedAt   *time.Time      `json:"decided_at,omitempty"`
	matchedJIDs json.RawMessage // stored form
}

// CreateAccessRequest records a pending request. The caller (the MCP tool)
// returns only the ID: the matched chat names are for the operator.
func (s *Store) CreateAccessRequest(ctx context.Context, query, reason string) (int64, error) {
	query = strings.TrimSpace(query)
	if query == "" || len(query) > 200 {
		return 0, errors.New("query must be 1-200 characters")
	}
	if len(reason) > 500 {
		reason = reason[:500]
	}
	var pending int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM access_requests WHERE status = 'pending'").Scan(&pending); err != nil {
		return 0, err
	}
	if pending >= maxPendingRequests {
		return 0, fmt.Errorf("there are already %d pending access requests; ask the user to review them first", pending)
	}
	matches, err := s.ResolveChats(ctx, query, 10)
	if err != nil {
		return 0, err
	}
	jids := make([]string, 0, len(matches))
	for _, m := range matches {
		jids = append(jids, m.JID)
	}
	raw, _ := json.Marshal(jids)
	res, err := s.db.ExecContext(ctx,
		"INSERT INTO access_requests (query, reason, matched_jids, status, created_at) VALUES (?, ?, ?, 'pending', ?)",
		query, nullIfEmpty(strings.TrimSpace(reason)), string(raw), time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("create access request: %w", err)
	}
	return res.LastInsertId()
}

// ListAccessRequests returns requests with the given status ("" for all),
// newest first, with their matches resolved for display.
func (s *Store) ListAccessRequests(ctx context.Context, status string) ([]AccessRequest, error) {
	q := "SELECT id, query, COALESCE(reason, ''), matched_jids, status, created_at, decided_at FROM access_requests"
	var args []any
	if status != "" {
		q += " WHERE status = ?"
		args = append(args, status)
	}
	q += " ORDER BY id DESC LIMIT 200"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list access requests: %w", err)
	}
	var out []AccessRequest
	for rows.Next() {
		var r AccessRequest
		var raw string
		var decided sql.NullTime
		if err := rows.Scan(&r.ID, &r.Query, &r.Reason, &raw, &r.Status, &r.CreatedAt, &decided); err != nil {
			rows.Close()
			return nil, err
		}
		if decided.Valid {
			t := decided.Time
			r.DecidedAt = &t
		}
		r.matchedJIDs = json.RawMessage(raw)
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		var jids []string
		_ = json.Unmarshal(out[i].matchedJIDs, &jids)
		for _, jid := range jids {
			e := AccessEntry{JID: jid, IsGroup: strings.HasSuffix(jid, "@g.us")}
			if c, err := s.GetChat(ctx, jid, false); err == nil && c != nil {
				e.Name = c.Name
				e.LastMessageTime = c.LastMessageTime
			}
			if e.Name == "" {
				e.Name = s.addressBookName(ctx, jid)
			}
			out[i].Matches = append(out[i].Matches, e)
		}
	}
	return out, nil
}

// DecideAccessRequest approves or rejects a pending request. On approval,
// jids selects which of the request's matches to allow; empty means all.
// A JID that was not among the matches is refused.
func (s *Store) DecideAccessRequest(ctx context.Context, id int64, approve bool, jids []string) error {
	reqs, err := s.ListAccessRequests(ctx, "pending")
	if err != nil {
		return err
	}
	var req *AccessRequest
	for i := range reqs {
		if reqs[i].ID == id {
			req = &reqs[i]
		}
	}
	if req == nil {
		return fmt.Errorf("no pending access request %d", id)
	}
	status := "rejected"
	if approve {
		status = "approved"
		matched := map[string]bool{}
		for _, m := range req.Matches {
			matched[m.JID] = true
		}
		if len(jids) == 0 {
			for _, m := range req.Matches {
				jids = append(jids, m.JID)
			}
		}
		if len(jids) == 0 {
			return fmt.Errorf("request %d matched no chats; allow a chat directly instead", id)
		}
		for _, jid := range jids {
			if !matched[jid] {
				return fmt.Errorf("%s was not among the chats matched by request %d", jid, id)
			}
			if err := s.SetChatAccess(ctx, jid, AccessAllowed, fmt.Sprintf("approved request %d", id)); err != nil {
				return err
			}
		}
	}
	_, err = s.db.ExecContext(ctx, "UPDATE access_requests SET status = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
		status, time.Now().UTC(), id)
	return err
}
