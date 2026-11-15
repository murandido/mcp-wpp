package mcp

import (
	"context"
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
		mcp.WithBoolean("only_unread", mcp.Description("only incoming messages newer than what you last read in each chat (read state comes from your own devices' read receipts and mark_read; a chat never read counts as unread)")),
		mcp.WithBoolean("mentions_only", mcp.Description("only messages that @-mention you")),
		mcp.WithArray("keywords", mcp.Items(map[string]any{"type": "string"}), mcp.Description("only messages containing any of these words (case-insensitive; accent-insensitive prefix match when the full-text index is available)")),
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
