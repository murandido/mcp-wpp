package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// imageTextsSchema caches text extracted from images by local OCR, so an
// image is recognised at most once. Like transcripts, it lives in the
// encrypted messages.db and follows the message's retention.
const imageTextsSchema = `
CREATE TABLE IF NOT EXISTS image_texts (
	message_id TEXT NOT NULL,
	chat_jid TEXT NOT NULL,
	text TEXT NOT NULL,
	langs TEXT NOT NULL DEFAULT '',
	truncated BOOLEAN NOT NULL DEFAULT 0,
	created_at TIMESTAMP NOT NULL,
	PRIMARY KEY (message_id, chat_jid)
);
`

// ImageText is text extracted from an image message.
type ImageText struct {
	MessageID string    `json:"message_id"`
	ChatJID   string    `json:"chat_jid"`
	Text      string    `json:"text"`
	Langs     string    `json:"langs,omitempty"`
	Truncated bool      `json:"truncated,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// GetImageText returns the stored OCR text, or (nil, nil) when there is none.
func (s *Store) GetImageText(ctx context.Context, messageID, chatJID string) (*ImageText, error) {
	var t ImageText
	err := s.db.QueryRowContext(ctx, `
		SELECT message_id, chat_jid, text, langs, truncated, created_at
		FROM image_texts WHERE message_id = ? AND chat_jid = ?`, messageID, chatJID).
		Scan(&t.MessageID, &t.ChatJID, &t.Text, &t.Langs, &t.Truncated, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get image text: %w", err)
	}
	return &t, nil
}

// PutImageText stores (or replaces) OCR text.
func (s *Store) PutImageText(ctx context.Context, t ImageText) error {
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO image_texts (message_id, chat_jid, text, langs, truncated, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(message_id, chat_jid) DO UPDATE SET
			text = excluded.text, langs = excluded.langs, truncated = excluded.truncated,
			created_at = excluded.created_at`,
		t.MessageID, t.ChatJID, t.Text, t.Langs, t.Truncated, t.CreatedAt)
	if err != nil {
		return fmt.Errorf("put image text: %w", err)
	}
	return nil
}
