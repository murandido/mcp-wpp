package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Digest groupings.
const (
	DigestByChat   = "chat"
	DigestBySender = "sender"
)

// ChatDigest is the recent activity of one chat, or of one sender when the
// digest is grouped by sender (then Sender is set and Chat is the chat of the
// sender's most recent message).
type ChatDigest struct {
	Chat     Chat
	Sender   string    // grouping key when grouped by sender: "me" or the sender
	FromMe   bool      // the group is the account's own messages
	Total    int       // matching messages since the cut-off
	Messages []Message // the most recent ones, oldest first
}

// DigestParams selects the messages of a digest. Zero values keep the
// original behaviour: every message after Since, grouped by chat.
type DigestParams struct {
	Since    time.Time
	ChatJIDs []string // restrict to these chats
	// MaxPerGroup is how many of the most recent messages each group shows
	// (default 10); MaxGroups caps the number of groups (default 30).
	MaxPerGroup int
	MaxGroups   int
	// OnlyUnread keeps incoming messages newer than the chat's read mark
	// (MarkChatReadThrough). A chat with no recorded read counts as unread.
	OnlyUnread bool
	// MentionsOnly keeps messages that mention the account.
	MentionsOnly bool
	// Keywords keeps messages matching any of them (FTS5 when available).
	Keywords []string
	// GroupBy is DigestByChat (default) or DigestBySender.
	GroupBy string
}

// Digest returns chats with messages after since, most recently active
// first, each with its last maxPerChat messages. chatJIDs, when non-empty,
// restricts the digest to those chats. On a scoped store only allowed chats
// appear.
func (s *Store) Digest(ctx context.Context, since time.Time, chatJIDs []string, maxPerChat, maxChats int) ([]ChatDigest, error) {
	return s.DigestWith(ctx, DigestParams{Since: since, ChatJIDs: chatJIDs, MaxPerGroup: maxPerChat, MaxGroups: maxChats})
}

// senderKey is the SQL grouping key for a digest grouped by sender.
const senderKey = "CASE WHEN messages.is_from_me THEN 'me' ELSE messages.sender END"

// DigestWith is Digest with filters and grouping. On a scoped store only
// allowed chats appear, whatever the filters.
func (s *Store) DigestWith(ctx context.Context, p DigestParams) ([]ChatDigest, error) {
	if p.MaxPerGroup <= 0 {
		p.MaxPerGroup = 10
	}
	if p.MaxGroups <= 0 {
		p.MaxGroups = 30
	}
	bySender := p.GroupBy == DigestBySender
	if p.GroupBy != "" && p.GroupBy != DigestByChat && !bySender {
		return nil, fmt.Errorf("group_by must be %q or %q", DigestByChat, DigestBySender)
	}
	where, args := s.digestWhere(p)

	key := "messages.chat_jid"
	if bySender {
		key = senderKey
	}
	q := "SELECT " + key + ", count(*) FROM messages WHERE " + where +
		" GROUP BY 1 ORDER BY max(messages.timestamp) DESC LIMIT ?"
	rows, err := s.db.QueryContext(ctx, q, append(append([]any{}, args...), p.MaxGroups)...)
	if err != nil {
		return nil, fmt.Errorf("digest: %w", err)
	}
	type group struct {
		key   string
		total int
	}
	var groups []group
	for rows.Next() {
		var g group
		if err := rows.Scan(&g.key, &g.total); err != nil {
			rows.Close()
			return nil, err
		}
		groups = append(groups, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]ChatDigest, 0, len(groups))
	for _, g := range groups {
		msgs, err := s.digestMessages(ctx, where, args, key, g.key, p.MaxPerGroup)
		if err != nil {
			return nil, err
		}
		if len(msgs) == 0 {
			continue
		}
		// Messages are read newest first; a digest reads oldest first.
		for i, j := 0, len(msgs)-1; i < j; i, j = i+1, j-1 {
			msgs[i], msgs[j] = msgs[j], msgs[i]
		}
		cd := ChatDigest{Total: g.total, Messages: msgs}
		chatJID := g.key
		if bySender {
			cd.Sender = g.key
			cd.FromMe = g.key == "me"
			chatJID = msgs[len(msgs)-1].ChatJID
		}
		c, err := s.GetChat(ctx, chatJID, false)
		if err != nil || c == nil {
			continue
		}
		cd.Chat = *c
		out = append(out, cd)
	}
	return out, nil
}

// digestWhere builds the shared WHERE clause (without the keyword) and its
// arguments.
func (s *Store) digestWhere(p DigestParams) (string, []any) {
	clauses := []string{"messages.timestamp > ?"}
	args := []any{p.Since}
	if len(p.ChatJIDs) > 0 {
		clauses = append(clauses, "messages.chat_jid IN ("+placeholders(len(p.ChatJIDs))+")")
		for _, j := range p.ChatJIDs {
			args = append(args, j)
		}
	}
	if p.OnlyUnread {
		clauses = append(clauses, "messages.is_from_me = 0",
			msgEpoch+" > COALESCE((SELECT last_read_at FROM chat_read_state WHERE chat_read_state.chat_jid = messages.chat_jid), 0)")
	}
	if p.MentionsOnly {
		clauses = append(clauses, "messages.mentions_me = 1")
	}
	if kw, kwArgs := s.keywordClause(p.Keywords); kw != "" {
		clauses = append(clauses, kw)
		args = append(args, kwArgs...)
	}
	if s.scoped {
		// accessFilter alone would ignore a client token's chat set; the
		// token filter narrows it (it starts with " AND " or is empty).
		clauses = append(clauses, accessFilter("messages.chat_jid")+s.tokenFilter("messages.chat_jid"))
	}
	return strings.Join(clauses, " AND "), args
}

// keywordClause matches any of the keywords. Keywords of at least
// minFTSQuery characters use the FTS5 index (prefix, case- and
// accent-insensitive) when it is available; shorter ones, and every keyword
// without FTS5, use a case-insensitive substring match.
func (s *Store) keywordClause(keywords []string) (string, []any) {
	var (
		ors  []string
		args []any
		fts  []string
	)
	for _, k := range keywords {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if s.fts && len([]rune(k)) >= minFTSQuery {
			if m := ftsMatchQuery(k); m != "" {
				fts = append(fts, "("+strings.ReplaceAll(m, " ", " AND ")+")")
				continue
			}
		}
		ors = append(ors, `LOWER(messages.content) LIKE LOWER(?) ESCAPE '\'`)
		args = append(args, "%"+escapeLike(k)+"%")
	}
	if len(fts) > 0 {
		ors = append(ors, "messages.rowid IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?)")
		args = append(args, strings.Join(fts, " OR "))
	}
	if len(ors) == 0 {
		return "", nil
	}
	return "(" + strings.Join(ors, " OR ") + ")", args
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// digestMessages returns the newest limit messages of one group.
func (s *Store) digestMessages(ctx context.Context, where string, args []any, key, value string, limit int) ([]Message, error) {
	q := "SELECT " + listMessageColumns + " FROM messages JOIN chats ON messages.chat_jid = chats.jid WHERE " +
		where + " AND " + key + " = ? ORDER BY messages.timestamp DESC LIMIT ?"
	rows, err := s.db.QueryContext(ctx, q, append(append([]any{}, args...), value, limit)...)
	if err != nil {
		return nil, fmt.Errorf("digest messages: %w", err)
	}
	defer rows.Close()
	var out []Message
	for rows.Next() {
		m, err := s.scanListMessageRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// FormatDigest renders a digest as compact text for a model.
func (s *Store) FormatDigest(ctx context.Context, d []ChatDigest, since time.Time) string {
	if len(d) == 0 {
		return fmt.Sprintf("No messages in authorised chats since %s UTC.", since.UTC().Format("2006-01-02 15:04"))
	}
	bySender := d[0].Sender != ""
	var b strings.Builder
	sinceText := since.UTC().Format("2006-01-02 15:04")
	if bySender {
		fmt.Fprintf(&b, "Activity since %s UTC from %d sender(s):\n", sinceText, len(d))
	} else {
		fmt.Fprintf(&b, "Activity since %s UTC in %d chat(s):\n", sinceText, len(d))
	}
	for _, cd := range d {
		shown := len(cd.Messages)
		if bySender {
			name := "Me"
			if !cd.FromMe {
				name = s.GetSenderName(ctx, cd.Sender)
			}
			fmt.Fprintf(&b, "\n## %s (%s): %d new", name, cd.Sender, cd.Total)
		} else {
			name := cd.Chat.Name
			if name == "" {
				name = cd.Chat.JID
			}
			fmt.Fprintf(&b, "\n## %s (%s): %d new", name, cd.Chat.JID, cd.Total)
		}
		if shown < cd.Total {
			fmt.Fprintf(&b, ", last %d shown", shown)
		}
		b.WriteString("\n")
		b.WriteString(s.FormatMessagesList(ctx, cd.Messages, bySender))
	}
	return b.String()
}
