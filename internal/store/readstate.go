package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Read state and mentions, used by the digest filters.
//
// chat_read_state keeps, per chat, the time up to which the user has read it
// (Unix seconds, so comparisons never depend on how a driver formats
// timestamps). Read receipts and mark_read only move it forward;
// RewindChatRead (the mark_unread tool) is the one explicit way back. messages.mentions_me records at
// ingestion whether a message mentions the account; rows cached before the
// column existed stay false.

const readStateSchema = `
CREATE TABLE IF NOT EXISTS chat_read_state (
	chat_jid     TEXT PRIMARY KEY,
	last_read_at INTEGER NOT NULL,
	updated_at   TIMESTAMP NOT NULL
);
`

// msgEpoch is the SQL expression for a message's timestamp in Unix seconds.
const msgEpoch = "CAST(strftime('%s', messages.timestamp) AS INTEGER)"

// applyDigestSchema creates the read-state table and adds messages.mentions_me
// when it is missing. Idempotent.
func applyDigestSchema(db *sql.DB) error {
	if _, err := db.Exec(readStateSchema); err != nil {
		return fmt.Errorf("apply read state schema: %w", err)
	}
	has, err := hasColumn(db, "messages", "mentions_me")
	if err != nil {
		return err
	}
	if !has {
		if _, err := db.Exec("ALTER TABLE messages ADD COLUMN mentions_me BOOLEAN NOT NULL DEFAULT 0"); err != nil {
			return fmt.Errorf("add column mentions_me: %w", err)
		}
	}
	return nil
}

func hasColumn(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query("SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		return false, fmt.Errorf("table info %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// MarkChatReadThrough records that the user read chatJID up to the newest of
// the cached messages ids, or up to fallback when none of them is cached (or
// ids is empty). It never moves the read mark backwards. A zero fallback with
// no cached message is a no-op.
func (s *Store) MarkChatReadThrough(ctx context.Context, chatJID string, ids []string, fallback time.Time) error {
	if chatJID == "" {
		return nil
	}
	var newest sql.NullInt64
	if len(ids) > 0 {
		q := "SELECT max(" + msgEpoch + ") FROM messages WHERE chat_jid = ? AND id IN (" + placeholders(len(ids)) + ")"
		args := []any{chatJID}
		for _, id := range ids {
			args = append(args, id)
		}
		if err := s.db.QueryRowContext(ctx, q, args...).Scan(&newest); err != nil {
			return fmt.Errorf("read state: %w", err)
		}
	}
	at := newest.Int64
	if !newest.Valid {
		if fallback.IsZero() {
			return nil
		}
		at = fallback.Unix()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO chat_read_state (chat_jid, last_read_at, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (chat_jid) DO UPDATE SET
			last_read_at = max(chat_read_state.last_read_at, excluded.last_read_at),
			updated_at = excluded.updated_at`,
		chatJID, at, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("store read state: %w", err)
	}
	return nil
}

// ErrMessageNotFound means the message is not cached in that chat.
var ErrMessageNotFound = errors.New("message not found")

// RewindChatRead moves chatJID's read mark back so the digest's only_unread
// shows its messages again. With fromMessageID, the mark moves to just
// before that cached message, so it and every later message count as
// unread; without, the mark is cleared and the whole chat counts as unread.
// It never moves the mark forward, and it changes local bookkeeping only:
// nothing is sent to WhatsApp, and a later read receipt from the phone moves
// the mark forward again.
func (s *Store) RewindChatRead(ctx context.Context, chatJID, fromMessageID string) error {
	if chatJID == "" {
		return errors.New("chat_jid is required")
	}
	if fromMessageID == "" {
		if _, err := s.db.ExecContext(ctx, "DELETE FROM chat_read_state WHERE chat_jid = ?", chatJID); err != nil {
			return fmt.Errorf("rewind read state: %w", err)
		}
		return nil
	}
	var at sql.NullInt64
	err := s.db.QueryRowContext(ctx, "SELECT "+msgEpoch+" FROM messages WHERE chat_jid = ? AND id = ?", chatJID, fromMessageID).Scan(&at)
	if err == sql.ErrNoRows || err == nil && !at.Valid {
		return ErrMessageNotFound
	}
	if err != nil {
		return fmt.Errorf("rewind read state: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE chat_read_state
		SET last_read_at = min(last_read_at, ?), updated_at = ?
		WHERE chat_jid = ?`, at.Int64-1, time.Now().UTC(), chatJID); err != nil {
		return fmt.Errorf("rewind read state: %w", err)
	}
	return nil
}

// ChatLastRead returns the time up to which chatJID has been read, and false
// when no read has been recorded. It reads bookkeeping, not chat content, and
// is not scoped.
func (s *Store) ChatLastRead(ctx context.Context, chatJID string) (time.Time, bool, error) {
	var at int64
	err := s.db.QueryRowContext(ctx, "SELECT last_read_at FROM chat_read_state WHERE chat_jid = ?", chatJID).Scan(&at)
	if err == sql.ErrNoRows {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("read state: %w", err)
	}
	return time.Unix(at, 0).UTC(), true, nil
}

// SetMentionsMe flags a cached message as mentioning the account.
func (s *Store) SetMentionsMe(ctx context.Context, id, chatJID string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE messages SET mentions_me = 1 WHERE id = ? AND chat_jid = ?", id, chatJID)
	return err
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
