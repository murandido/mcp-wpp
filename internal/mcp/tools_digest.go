package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/murandido/mcp-wpp/internal/store"
)

type digestArgs struct {
	Since        string   `json:"since"`
	Hours        float64  `json:"hours"`
	ChatJIDs     []string `json:"chat_jids"`
	MaxPerChat   int      `json:"max_per_chat"`
	OnlyUnread   bool     `json:"only_unread"`
	MentionsOnly bool     `json:"mentions_only"`
	Keywords     []string `json:"keywords"`
	GroupBy      string   `json:"group_by"`
}

// maxDigestKeywords bounds the keyword list so one call cannot build an
// unbounded query.
const maxDigestKeywords = 20

func (s *Server) registerDigestTool() {
	tool := mcp.NewTool("digest",
		mcp.WithDescription(offlineSafePrefix+"Summarise recent activity: for every authorised chat with messages after a cut-off, the number of matching messages and the most recent ones, most active first, optionally only unread ones, ones that mention you, or ones matching keywords, grouped by chat or by sender. Read-only; no side effects. Use it for \"what did I miss\" questions instead of calling list_messages per chat; use list_messages to search or page further. Returns a formatted text block grouped by chat (or sender)."),
		mcp.WithString("since", mcp.Description("ISO-8601 UTC cut-off; overrides `hours`")),
		mcp.WithNumber("hours", mcp.Description("look back this many hours (default 24, max 720)")),
		mcp.WithArray("chat_jids", mcp.Items(map[string]any{"type": "string"}), mcp.Description("restrict to these chats ("+jidDesc+")")),
		mcp.WithNumber("max_per_chat", mcp.Description("most recent messages to show per group (default 10, max 50)")),
		mcp.WithBoolean("only_unread", mcp.Description("only incoming messages newer than what you last read in each chat (read state comes from your own devices' read receipts and mark_read, and mark_unread moves it back; a chat never read counts as unread)")),
		mcp.WithBoolean("mentions_only", mcp.Description("only messages that @-mention you")),
		mcp.WithArray("keywords", mcp.Items(map[string]any{"type": "string"}), mcp.Description("only messages containing any of these words (case- and accent-insensitive; prefix match when the full-text index is available, substring match otherwise)")),
		mcp.WithString("group_by", mcp.Enum(store.DigestByChat, store.DigestBySender), mcp.Description("`chat` (default) or `sender`")),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
	)
	s.mcp.AddTool(tool, mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a digestArgs) (*mcp.CallToolResult, error) {
		since := time.Now().UTC().Add(-24 * time.Hour)
		switch {
		case a.Since != "":
			t, err := parseTimestamp(a.Since)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			since = t
		case a.Hours > 0:
			h := min(a.Hours, 720)
			since = time.Now().UTC().Add(-time.Duration(h * float64(time.Hour)))
		}
		per := a.MaxPerChat
		if per > 50 {
			per = 50
		}
		switch a.GroupBy {
		case "", store.DigestByChat, store.DigestBySender:
		default:
			return mcp.NewToolResultError("group_by must be \"chat\" or \"sender\""), nil
		}
		if len(a.Keywords) > maxDigestKeywords {
			return mcp.NewToolResultError("at most 20 keywords"), nil
		}
		jids := make([]string, 0, len(a.ChatJIDs))
		for _, j := range a.ChatJIDs {
			if jid := s.chatJIDFor(j); jid != "" {
				jids = append(jids, jid)
			}
		}
		st := s.store(ctx)
		// Asking for specific chats that all fail to resolve must not widen
		// the digest to every authorised chat.
		if len(a.ChatJIDs) > 0 && len(jids) == 0 {
			return mcp.NewToolResultText(untrustedPreamble + st.FormatDigest(ctx, nil, since)), nil
		}
		d, err := st.DigestWith(ctx, store.DigestParams{
			Since:        since,
			ChatJIDs:     jids,
			MaxPerGroup:  per,
			MaxGroups:    30,
			OnlyUnread:   a.OnlyUnread,
			MentionsOnly: a.MentionsOnly,
			Keywords:     a.Keywords,
			GroupBy:      a.GroupBy,
		})
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(untrustedPreamble + st.FormatDigest(ctx, d, since)), nil
	}))
}

type markUnreadArgs struct {
	ChatJID   string `json:"chat_jid"`
	MessageID string `json:"message_id"`
}

// registerMarkUnread wires mark_unread: the explicit way to move the
// digest's read mark back. It changes local bookkeeping only.
func (s *Server) registerMarkUnread() {
	tool := mcp.NewTool("mark_unread",
		mcp.WithDescription("Move a chat's local read mark back so digest with only_unread shows its messages again: from message_id onward, or the whole chat when message_id is omitted. Changes only this server's read state, never moves the mark forward, and sends nothing to WhatsApp (your phone keeps its own unread state; a later read on any device moves the mark forward again); use mark_read to send read receipts. Returns a plain-text confirmation."),
		mcp.WithString("chat_jid", mcp.Required(), mcp.Description(jidDesc)),
		mcp.WithString("message_id", mcp.Description("optional id of a cached message in the chat, as returned by list_messages; it and every later message count as unread")),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
	)
	s.mcp.AddTool(tool, mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a markUnreadArgs) (*mcp.CallToolResult, error) {
		if r := requireNonEmpty("chat_jid", a.ChatJID); r != nil {
			return r, nil
		}
		jid := s.chatJIDFor(a.ChatJID)
		if err := s.store(ctx).RewindChatRead(ctx, jid, a.MessageID); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if a.MessageID != "" {
			return mcp.NewToolResultText(fmt.Sprintf("Marked %s unread from message %s (local digest read state only)", jid, a.MessageID)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Marked %s unread (local digest read state only)", jid)), nil
	}))
}
