package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// documentTextsSchema caches text extracted from document messages (PDFs
// and plain-text files), so a document is read at most once. Like
// transcripts, it lives in the encrypted messages.db and follows the
// message's retention.
const documentTextsSchema = `
CREATE TABLE IF NOT EXISTS document_texts (
	message_id TEXT NOT NULL,
	chat_jid TEXT NOT NULL,
	text TEXT NOT NULL,
	kind TEXT NOT NULL DEFAULT '',
	truncated BOOLEAN NOT NULL DEFAULT 0,
	created_at TIMESTAMP NOT NULL,
	PRIMARY KEY (message_id, chat_jid)
);
`

// DocumentText is text extracted from a document message.
type DocumentText struct {
	MessageID string    `json:"message_id"`
	ChatJID   string    `json:"chat_jid"`
	Text      string    `json:"text"`
	Kind      string    `json:"kind,omitempty"` // pdf or text
	Truncated bool      `json:"truncated,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// GetDocumentText returns the stored text, or (nil, nil) when there is none.
func (s *Store) GetDocumentText(ctx context.Context, messageID, chatJID string) (*DocumentText, error) {
	var t DocumentText
	err := s.db.QueryRowContext(ctx, `
		SELECT message_id, chat_jid, text, kind, truncated, created_at
		FROM document_texts WHERE message_id = ? AND chat_jid = ?`, messageID, chatJID).
		Scan(&t.MessageID, &t.ChatJID, &t.Text, &t.Kind, &t.Truncated, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get document text: %w", err)
	}
	return &t, nil
}

// PutDocumentText stores (or replaces) document text.
func (s *Store) PutDocumentText(ctx context.Context, t DocumentText) error {
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO document_texts (message_id, chat_jid, text, kind, truncated, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(message_id, chat_jid) DO UPDATE SET
			text = excluded.text, kind = excluded.kind, truncated = excluded.truncated,
			created_at = excluded.created_at`,
		t.MessageID, t.ChatJID, t.Text, t.Kind, t.Truncated, t.CreatedAt)
	if err != nil {
		return fmt.Errorf("put document text: %w", err)
	}
	return nil
}
