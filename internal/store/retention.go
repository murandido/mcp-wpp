package store

import (
	"context"
	"fmt"
	"time"
)

// PurgedMessage identifies a deleted message whose cached media, if any,
// the caller should remove.
type PurgedMessage struct {
	ID      string
	ChatJID string
}

// PurgeBefore deletes messages older than cutoff together with their
// transcripts, OCR text and poll votes, in one transaction. The FTS index follows
// through its delete trigger. Chats stay, so access decisions survive.
func (s *Store) PurgeBefore(ctx context.Context, cutoff time.Time) ([]PurgedMessage, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, "SELECT id, chat_jid FROM messages WHERE timestamp < ?", cutoff)
	if err != nil {
		return nil, fmt.Errorf("select expired messages: %w", err)
	}
	var out []PurgedMessage
	for rows.Next() {
		var p PurgedMessage
		if err := rows.Scan(&p.ID, &p.ChatJID); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	for _, q := range []string{
		"DELETE FROM transcripts WHERE (message_id, chat_jid) IN (SELECT id, chat_jid FROM messages WHERE timestamp < ?)",
		"DELETE FROM image_texts WHERE (message_id, chat_jid) IN (SELECT id, chat_jid FROM messages WHERE timestamp < ?)",
		"DELETE FROM document_texts WHERE (message_id, chat_jid) IN (SELECT id, chat_jid FROM messages WHERE timestamp < ?)",
		"DELETE FROM poll_votes WHERE (poll_message_id, poll_chat_jid) IN (SELECT id, chat_jid FROM messages WHERE timestamp < ?)",
		"DELETE FROM messages WHERE timestamp < ?",
	} {
		if _, err := tx.ExecContext(ctx, q, cutoff); err != nil {
			return nil, fmt.Errorf("purge: %w", err)
		}
	}
	return out, tx.Commit()
}

// Vacuum rebuilds messages.db so deleted pages are not left behind.
func (s *Store) Vacuum(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "VACUUM")
	return err
}
