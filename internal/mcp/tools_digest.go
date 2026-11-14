package mcp

import (
	"context"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

type digestArgs struct {
	Since      string   `json:"since"`
	Hours      float64  `json:"hours"`
	ChatJIDs   []string `json:"chat_jids"`
	MaxPerChat int      `json:"max_per_chat"`
}

func (s *Server) registerDigestTool() {
	tool := mcp.NewTool("digest",
		mcp.WithDescription(offlineSafePrefix+"Summarise recent activity: for every authorised chat with messages after a cut-off, the number of new messages and the most recent ones, most active chats first. Read-only; no side effects. Use it for \"what did I miss\" questions instead of calling list_messages per chat; use list_messages to search or page further. Returns a formatted text block grouped by chat."),
		mcp.WithString("since", mcp.Description("ISO-8601 UTC cut-off; overrides `hours`")),
		mcp.WithNumber("hours", mcp.Description("look back this many hours (default 24, max 720)")),
		mcp.WithArray("chat_jids", mcp.Items(map[string]any{"type": "string"}), mcp.Description("restrict to these chats ("+jidDesc+")")),
		mcp.WithNumber("max_per_chat", mcp.Description("most recent messages to show per chat (default 10, max 50)")),
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
		jids := make([]string, 0, len(a.ChatJIDs))
		for _, j := range a.ChatJIDs {
			if jid := s.chatJIDFor(j); jid != "" {
				jids = append(jids, jid)
			}
		}
		st := s.store()
		d, err := st.Digest(ctx, since, jids, per, 30)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(st.FormatDigest(ctx, d, since)), nil
	}))
}
