package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Audit log. Every MCP tool call and resource read, and every state-changing
// operator action, gets one row: who, what, which chat, the outcome and how
// long it took. It deliberately holds no message text, no tool arguments
// other than the targeted chat, and no results.

const auditSchema = `
CREATE TABLE IF NOT EXISTS audit_log (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	at          TIMESTAMP NOT NULL,
	actor       TEXT NOT NULL,
	token_id    INTEGER,
	kind        TEXT NOT NULL CHECK (kind IN ('tool', 'resource', 'admin')),
	action      TEXT NOT NULL,
	chat_jid    TEXT,
	detail      TEXT,
	outcome     TEXT NOT NULL CHECK (outcome IN ('ok', 'error', 'denied', 'proposed')),
	duration_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS audit_log_at ON audit_log (at);
`

// Audit entry kinds.
const (
	AuditTool     = "tool"
	AuditResource = "resource"
	AuditAdmin    = "admin"
)

// Audit outcomes.
const (
	OutcomeOK       = "ok"
	OutcomeError    = "error"
	OutcomeDenied   = "denied"
	OutcomeProposed = "proposed"
)

// maxAuditDetail bounds the free-form detail of admin entries.
const maxAuditDetail = 300

// AuditEntry is one audit row.
type AuditEntry struct {
	ID       int64     `json:"id"`
	At       time.Time `json:"at"`
	Actor    string    `json:"actor"`
	TokenID  int64     `json:"token_id,omitempty"`
	Kind     string    `json:"kind"`
	Action   string    `json:"action"`
	ChatJID  string    `json:"chat_jid,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	Outcome  string    `json:"outcome"`
	Duration int64     `json:"duration_ms"`
}

// RecordAudit appends e. A zero At is set to now.
func (s *Store) RecordAudit(ctx context.Context, e AuditEntry) error {
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	switch e.Kind {
	case AuditTool, AuditResource, AuditAdmin:
	default:
		return fmt.Errorf("unknown audit kind %q", e.Kind)
	}
	switch e.Outcome {
	case OutcomeOK, OutcomeError, OutcomeDenied, OutcomeProposed:
	default:
		return fmt.Errorf("unknown audit outcome %q", e.Outcome)
	}
	if e.Actor == "" || e.Action == "" {
		return errors.New("audit entry needs an actor and an action")
	}
	if len(e.Detail) > maxAuditDetail {
		e.Detail = e.Detail[:maxAuditDetail]
	}
	var tokenID any
	if e.TokenID != 0 {
		tokenID = e.TokenID
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_log (at, actor, token_id, kind, action, chat_jid, detail, outcome, duration_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.At.UTC(), e.Actor, tokenID, e.Kind, e.Action, nullIfEmpty(e.ChatJID), nullIfEmpty(e.Detail), e.Outcome, e.Duration)
	if err != nil {
		return fmt.Errorf("record audit: %w", err)
	}
	return nil
}

// AuditFilter selects audit rows. Zero fields do not filter.
type AuditFilter struct {
	Since time.Time `json:"since"`
	// Actor matches "operator", a token name, or "token:<name>".
	Actor   string `json:"actor,omitempty"`
	ChatJID string `json:"chat_jid,omitempty"`
	Limit   int    `json:"limit,omitempty"`
}

// ListAudit returns matching rows, newest first (at most 1000).
func (s *Store) ListAudit(ctx context.Context, f AuditFilter) ([]AuditEntry, error) {
	q := "SELECT id, at, actor, COALESCE(token_id, 0), kind, action, COALESCE(chat_jid, ''), COALESCE(detail, ''), outcome, duration_ms FROM audit_log WHERE 1=1"
	var args []any
	if !f.Since.IsZero() {
		q += " AND at >= ?"
		args = append(args, f.Since.UTC())
	}
	if a := strings.TrimSpace(f.Actor); a != "" {
		q += " AND (actor = ? OR actor = ?)"
		args = append(args, a, "token:"+strings.TrimPrefix(a, "token:"))
	}
	if c := strings.TrimSpace(f.ChatJID); c != "" {
		q += " AND chat_jid = ?"
		args = append(args, c)
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	limit = min(limit, 1000)
	q += " ORDER BY at DESC, id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at sql.NullTime
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.TokenID, &e.Kind, &e.Action, &e.ChatJID, &e.Detail, &e.Outcome, &e.Duration); err != nil {
			return nil, err
		}
		e.At = at.Time
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneAudit deletes rows older than cutoff and returns how many it removed.
func (s *Store) PruneAudit(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM audit_log WHERE at < ?", cutoff.UTC())
	if err != nil {
		return 0, fmt.Errorf("prune audit: %w", err)
	}
	return res.RowsAffected()
}

// RunAuditPruning deletes audit rows older than age now and then hourly,
// until ctx ends. logf reports failures.
func (s *Store) RunAuditPruning(ctx context.Context, age time.Duration, logf func(format string, args ...any)) {
	run := func() {
		if _, err := s.PruneAudit(ctx, time.Now().Add(-age)); err != nil && ctx.Err() == nil {
			logf("audit: %v", err)
		}
	}
	run()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
