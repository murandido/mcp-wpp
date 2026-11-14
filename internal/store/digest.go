package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ChatDigest is the recent activity of one chat.
type ChatDigest struct {
	Chat     Chat
	Total    int       // messages since the cut-off
	Messages []Message // the most recent ones, oldest first
}

// Digest returns chats with messages after since, most recently active
// first, each with its last maxPerChat messages. chatJIDs, when non-empty,
// restricts the digest to those chats. On a scoped store only allowed chats
// appear.
func (s *Store) Digest(ctx context.Context, since time.Time, chatJIDs []string, maxPerChat, maxChats int) ([]ChatDigest, error) {
	if maxPerChat <= 0 {
		maxPerChat = 10
	}
	if maxChats <= 0 {
		maxChats = 30
	}
	q := `SELECT chat_jid, count(*) FROM messages WHERE timestamp > ?` + s.scopeClause("chat_jid")
	args := []any{since}
	if len(chatJIDs) > 0 {
		q += " AND chat_jid IN (" + strings.TrimSuffix(strings.Repeat("?,", len(chatJIDs)), ",") + ")"
		for _, j := range chatJIDs {
			args = append(args, j)
		}
	}
	q += " GROUP BY chat_jid ORDER BY max(timestamp) DESC LIMIT ?"
	args = append(args, maxChats)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("digest: %w", err)
	}
	type row struct {
		jid   string
		total int
	}
	var chats []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.jid, &r.total); err != nil {
			rows.Close()
			return nil, err
		}
		chats = append(chats, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]ChatDigest, 0, len(chats))
	for _, r := range chats {
		c, err := s.GetChat(ctx, r.jid, false)
		if err != nil || c == nil {
			continue
		}
		msgs, err := s.ListMessages(ctx, ListMessagesParams{ChatJID: r.jid, After: since, Limit: maxPerChat})
		if err != nil {
			return nil, err
		}
		// ListMessages is newest first; a digest reads oldest first.
		for i, j := 0, len(msgs)-1; i < j; i, j = i+1, j-1 {
			msgs[i], msgs[j] = msgs[j], msgs[i]
		}
		out = append(out, ChatDigest{Chat: *c, Total: r.total, Messages: msgs})
	}
	return out, nil
}

// FormatDigest renders a digest as compact text for a model.
func (s *Store) FormatDigest(ctx context.Context, d []ChatDigest, since time.Time) string {
	if len(d) == 0 {
		return fmt.Sprintf("No messages in authorised chats since %s UTC.", since.UTC().Format("2006-01-02 15:04"))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Activity since %s UTC in %d chat(s):\n", since.UTC().Format("2006-01-02 15:04"), len(d))
	for _, cd := range d {
		name := cd.Chat.Name
		if name == "" {
			name = cd.Chat.JID
		}
		shown := len(cd.Messages)
		fmt.Fprintf(&b, "\n## %s (%s): %d new", name, cd.Chat.JID, cd.Total)
		if shown < cd.Total {
			fmt.Fprintf(&b, ", last %d shown", shown)
		}
		b.WriteString("\n")
		b.WriteString(s.FormatMessagesList(ctx, cd.Messages, false))
	}
	return b.String()
}
