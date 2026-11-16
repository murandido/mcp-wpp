package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Chat notes: a living summary of each chat, written by the MCP client and
// kept by the server. The client reads the summary plus the messages after
// its watermark, merges them and writes the summary back, so the notes grow
// every time they are used. Notes are local state, never sent to WhatsApp.
// They are derived from other people's messages and are served as untrusted
// data. Denying or resetting a chat's access deletes its notes; retention
// does not, because the summary is what outlives old messages.

const chatNotesSchema = `
CREATE TABLE IF NOT EXISTS chat_notes (
	chat_jid         TEXT PRIMARY KEY,
	summary          TEXT NOT NULL,
	covered_until_ts INTEGER NOT NULL DEFAULT 0,
	covered_until_id TEXT NOT NULL DEFAULT '',
	version          INTEGER NOT NULL,
	updated_at       TIMESTAMP NOT NULL,
	updated_by       TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS chat_notes_history (
	chat_jid   TEXT NOT NULL,
	version    INTEGER NOT NULL,
	summary    TEXT NOT NULL,
	updated_at TIMESTAMP NOT NULL,
	updated_by TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (chat_jid, version)
);
`

// MaxNotesBytes bounds a chat's summary.
const MaxNotesBytes = 8 << 10

// notesHistoryKeep is how many earlier versions are kept per chat.
const notesHistoryKeep = 10

// ErrNotesConflict means the notes changed since the caller read them.
var ErrNotesConflict = errors.New("the notes changed since you read them; read them again with get_chat_notes, merge, and retry with the new version")

// ChatNotes is a chat's current summary. Version 0 means no notes yet.
type ChatNotes struct {
	ChatJID        string    `json:"chat_jid"`
	Summary        string    `json:"summary"`
	Version        int       `json:"version"`
	CoveredUntilID string    `json:"covered_until_message_id,omitempty"`
	CoveredUntil   time.Time `json:"covered_until,omitempty"`
	UpdatedAt      time.Time `json:"updated_at,omitempty"`
	UpdatedBy      string    `json:"updated_by,omitempty"`
}

// ChatNotesVersion is one stored version of a chat's notes.
type ChatNotesVersion struct {
	Version   int       `json:"version"`
	Summary   string    `json:"summary"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

// GetChatNotes returns jid's notes; a chat without notes gets version 0 and
// an empty summary. On a scoped view a hidden chat gets ErrChatNotFound.
func (s *Store) GetChatNotes(ctx context.Context, jid string) (ChatNotes, error) {
	if err := s.requireVisibleChat(ctx, jid); err != nil {
		return ChatNotes{}, err
	}
	n := ChatNotes{ChatJID: jid}
	var ts int64
	var updated sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT summary, version, covered_until_id, covered_until_ts, updated_at, updated_by
		FROM chat_notes WHERE chat_jid = ?`+s.scopeClause("chat_notes.chat_jid"), jid).
		Scan(&n.Summary, &n.Version, &n.CoveredUntilID, &ts, &updated, &n.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return n, nil
	}
	if err != nil {
		return ChatNotes{}, fmt.Errorf("read chat notes: %w", err)
	}
	if ts > 0 {
		n.CoveredUntil = time.Unix(ts, 0).UTC()
	}
	if updated.Valid {
		n.UpdatedAt = updated.Time.UTC()
	}
	return n, nil
}

// ErrChatNotFound is returned for a chat that is hidden or not cached; the
// two are indistinguishable on purpose.
var ErrChatNotFound = errors.New("chat not found")

// requireVisibleChat refuses chats the view cannot see. The unscoped store
// (operator commands) only requires a JID.
func (s *Store) requireVisibleChat(ctx context.Context, jid string) error {
	if strings.TrimSpace(jid) == "" {
		return errors.New("chat_jid is required")
	}
	if !s.scoped {
		return nil
	}
	ok, err := s.ChatAllowed(ctx, jid)
	if err != nil {
		return err
	}
	if !ok {
		return ErrChatNotFound
	}
	return nil
}

// UpdateChatNotes replaces jid's summary. expectedVersion must be the
// version the caller read (0 for a chat without notes), or ErrNotesConflict
// is returned. coveredUntilID, when set, must be a cached message of the
// chat; the watermark only moves forward. The previous version is kept in
// the history. The author is taken from the request identity.
func (s *Store) UpdateChatNotes(ctx context.Context, jid, summary, coveredUntilID string, expectedVersion int) (ChatNotes, error) {
	if err := s.requireVisibleChat(ctx, jid); err != nil {
		return ChatNotes{}, err
	}
	summary = strings.TrimSpace(summary)
	if summary == "" {
		return ChatNotes{}, errors.New("summary is empty; use clear to delete notes")
	}
	if len(summary) > MaxNotesBytes {
		return ChatNotes{}, fmt.Errorf("summary is %d bytes; keep it under %d by condensing older points", len(summary), MaxNotesBytes)
	}
	if !utf8.ValidString(summary) {
		return ChatNotes{}, errors.New("summary is not valid UTF-8")
	}
	var coveredTS int64
	if coveredUntilID != "" {
		var at sql.NullInt64
		err := s.db.QueryRowContext(ctx, "SELECT "+msgEpoch+" FROM messages WHERE chat_jid = ? AND id = ?", jid, coveredUntilID).Scan(&at)
		if errors.Is(err, sql.ErrNoRows) || err == nil && !at.Valid {
			return ChatNotes{}, fmt.Errorf("covered_until_message_id: %w in this chat", ErrMessageNotFound)
		}
		if err != nil {
			return ChatNotes{}, fmt.Errorf("update chat notes: %w", err)
		}
		coveredTS = at.Int64
	}
	by, _ := creatorFrom(ctx)
	now := time.Now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ChatNotes{}, err
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit

	var cur struct {
		summary, id, by string
		version         int
		ts              int64
		at              time.Time
	}
	err = tx.QueryRowContext(ctx, "SELECT summary, version, covered_until_id, covered_until_ts, updated_at, updated_by FROM chat_notes WHERE chat_jid = ?", jid).
		Scan(&cur.summary, &cur.version, &cur.id, &cur.ts, &cur.at, &cur.by)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ChatNotes{}, fmt.Errorf("update chat notes: %w", err)
	}
	if cur.version != expectedVersion {
		return ChatNotes{}, ErrNotesConflict
	}
	// The watermark never moves back.
	if coveredTS < cur.ts || coveredUntilID == "" {
		coveredTS, coveredUntilID = cur.ts, cur.id
	}
	next := cur.version + 1
	if exists {
		if _, err := tx.ExecContext(ctx, "INSERT OR REPLACE INTO chat_notes_history (chat_jid, version, summary, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
			jid, cur.version, cur.summary, cur.at, cur.by); err != nil {
			return ChatNotes{}, fmt.Errorf("keep notes history: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM chat_notes_history WHERE chat_jid = ? AND version <= ?", jid, cur.version-notesHistoryKeep); err != nil {
			return ChatNotes{}, fmt.Errorf("trim notes history: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO chat_notes (chat_jid, summary, covered_until_ts, covered_until_id, version, updated_at, updated_by)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (chat_jid) DO UPDATE SET summary = excluded.summary, covered_until_ts = excluded.covered_until_ts,
			covered_until_id = excluded.covered_until_id, version = excluded.version, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
		jid, summary, coveredTS, coveredUntilID, next, now, by); err != nil {
		return ChatNotes{}, fmt.Errorf("store chat notes: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ChatNotes{}, err
	}
	n := ChatNotes{ChatJID: jid, Summary: summary, Version: next, CoveredUntilID: coveredUntilID, UpdatedAt: now, UpdatedBy: by}
	if coveredTS > 0 {
		n.CoveredUntil = time.Unix(coveredTS, 0).UTC()
	}
	return n, nil
}

// ChatNotesHistory returns jid's earlier versions, newest first.
func (s *Store) ChatNotesHistory(ctx context.Context, jid string) ([]ChatNotesVersion, error) {
	if err := s.requireVisibleChat(ctx, jid); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT version, summary, updated_at, updated_by FROM chat_notes_history
		WHERE chat_jid = ?`+s.scopeClause("chat_notes_history.chat_jid")+` ORDER BY version DESC`, jid)
	if err != nil {
		return nil, fmt.Errorf("read notes history: %w", err)
	}
	defer rows.Close()
	var out []ChatNotesVersion
	for rows.Next() {
		var v ChatNotesVersion
		if err := rows.Scan(&v.Version, &v.Summary, &v.UpdatedAt, &v.UpdatedBy); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// RevertChatNotes makes an earlier version current again, as a new version
// (the history keeps what it replaced).
func (s *Store) RevertChatNotes(ctx context.Context, jid string, version int) (ChatNotes, error) {
	cur, err := s.GetChatNotes(ctx, jid)
	if err != nil {
		return ChatNotes{}, err
	}
	var summary string
	err = s.db.QueryRowContext(ctx, "SELECT summary FROM chat_notes_history WHERE chat_jid = ? AND version = ?", jid, version).Scan(&summary)
	if errors.Is(err, sql.ErrNoRows) {
		return ChatNotes{}, fmt.Errorf("version %d is not in the history of %s", version, jid)
	}
	if err != nil {
		return ChatNotes{}, err
	}
	return s.UpdateChatNotes(ctx, jid, summary, "", cur.Version)
}

// ClearChatNotes deletes jid's notes and their history.
func (s *Store) ClearChatNotes(ctx context.Context, jid string) error {
	if err := s.requireVisibleChat(ctx, jid); err != nil {
		return err
	}
	return deleteChatNotes(ctx, s.db, jid)
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func deleteChatNotes(ctx context.Context, db execer, jid string) error {
	if _, err := db.ExecContext(ctx, "DELETE FROM chat_notes WHERE chat_jid = ?", jid); err != nil {
		return fmt.Errorf("delete chat notes: %w", err)
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM chat_notes_history WHERE chat_jid = ?", jid); err != nil {
		return fmt.Errorf("delete notes history: %w", err)
	}
	return nil
}

// NotesVersions returns the current notes version of each chat that has
// notes, for operator listings.
func (s *Store) NotesVersions(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT chat_jid, version FROM chat_notes WHERE 1"+s.scopeClause("chat_notes.chat_jid"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var jid string
		var v int
		if err := rows.Scan(&jid, &v); err != nil {
			return nil, err
		}
		out[jid] = v
	}
	return out, rows.Err()
}

// MessagesAfterNotes returns up to limit messages of jid newer than the
// notes' watermark, oldest first, and whether more remain. With no
// watermark it returns the newest limit messages (oldest first), so a first
// summary starts from recent history.
func (s *Store) MessagesAfterNotes(ctx context.Context, n ChatNotes, limit int) ([]Message, bool, error) {
	if err := s.requireVisibleChat(ctx, n.ChatJID); err != nil {
		return nil, false, err
	}
	if limit <= 0 {
		limit = 100
	}
	cols := listMessageColumns
	base := ` FROM messages JOIN chats ON messages.chat_jid = chats.jid WHERE messages.chat_jid = ?` + s.scopeClause("messages.chat_jid")
	var q string
	args := []any{n.ChatJID}
	if n.CoveredUntil.IsZero() {
		q = "SELECT * FROM (SELECT " + cols + base + " ORDER BY messages.timestamp DESC, messages.id DESC LIMIT ?) ORDER BY 1, 7"
		args = append(args, limit+1)
	} else {
		ts := n.CoveredUntil.Unix()
		q = "SELECT " + cols + base + " AND (" + msgEpoch + " > ? OR (" + msgEpoch + " = ? AND messages.id > ?)) ORDER BY messages.timestamp, messages.id LIMIT ?"
		args = append(args, ts, ts, n.CoveredUntilID, limit+1)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, false, fmt.Errorf("messages after notes: %w", err)
	}
	defer rows.Close()
	var msgs []Message
	for rows.Next() {
		m, err := s.scanListMessageRow(rows)
		if err != nil {
			return nil, false, err
		}
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(msgs) > limit
	if more {
		if n.CoveredUntil.IsZero() {
			msgs = msgs[1:] // the oldest of limit+1 is the extra one
		} else {
			msgs = msgs[:limit]
		}
	}
	return msgs, more, nil
}
