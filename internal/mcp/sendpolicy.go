package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/murandido/mcp-wpp/internal/store"
)

// Per-chat send policy (see internal/store/sendpolicy.go). The confirmation
// middleware resolves the chat a write tool targets (its toolAccessScope
// argument) and applies that chat's policy:
//
//   - none:    the call is refused, even in -write mode;
//   - confirm: the call becomes an outbox proposal;
//   - direct:  the call acts immediately.
//
// Chats without an explicit policy use DefaultSendPolicy, derived from
// -confirm-sends. Tools that target no chat (privacy settings, create_group,
// …) always use the default. The access middleware runs first, so a hidden
// chat is refused with the usual "chat not found" before its send policy is
// ever consulted (invariant 3); the policy never widens visibility.

// DefaultSendPolicy is the policy for chats without an explicit one:
// confirm with -confirm-sends (the default), direct without it. It reports
// none in read-only mode, where write tools are not exposed at all.
func (s *Server) DefaultSendPolicy() string {
	switch {
	case s.readOnly:
		return store.SendNone
	case s.confirmSends:
		return store.SendConfirm
	default:
		return store.SendDirect
	}
}

// SetClock replaces the clock used for scheduling (tests).
func (s *Server) SetClock(now func() time.Time) { s.now = now }

func (s *Server) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// targetChatRef returns the chat argument of a call to tool, or "" when the
// tool targets no chat.
func targetChatRef(tool string, args map[string]any) string {
	scope := toolAccessScope[tool]
	if scope.chatArg == "" {
		return ""
	}
	v, _ := args[scope.chatArg].(string)
	return v
}

// sendPolicyFor returns the effective send policy for a chat reference ("" for
// tools that target no chat). It fails closed: an unreadable policy is an error.
func (s *Server) sendPolicyFor(ctx context.Context, ref string) (string, error) {
	if ref == "" || s.client == nil {
		return s.DefaultSendPolicy(), nil
	}
	p, err := s.client.Store().ChatSendPolicy(ctx, s.chatJIDFor(ref))
	if err != nil {
		return "", err
	}
	if p == store.SendDefault {
		return s.DefaultSendPolicy(), nil
	}
	return p, nil
}

func sendRefusedText(ref string) string {
	return fmt.Sprintf("sending to %s is turned off by the user (send policy \"none\"); nothing was sent. Tell the user; only they can change it (`wpp-mcp access send`).", ref)
}

// writeBlocked re-checks, at execution time, that a write may still reach its
// chat: the chat must be visible and its send policy must not be none. It
// returns the refusal text, or "" when the write may proceed.
func (s *Server) writeBlocked(ctx context.Context, tool string, args map[string]any) string {
	ref := targetChatRef(tool, args)
	if ref == "" {
		return ""
	}
	if !s.allowedChat(ctx, ref) {
		return toolText(chatNotFound(ref))
	}
	if reason := s.ownChatBlocked(ref); reason != "" {
		return reason
	}
	policy, err := s.sendPolicyFor(ctx, ref)
	if err != nil {
		return "cannot read the send policy: " + err.Error()
	}
	if policy == store.SendNone {
		return sendRefusedText(ref)
	}
	return ""
}

func toolText(res *mcp.CallToolResult) string {
	for _, c := range res.Content {
		if t, ok := c.(mcp.TextContent); ok {
			return t.Text
		}
	}
	return ""
}

type sendPolicyKey struct{}

// withSendPolicy hands the resolved policy to tools that apply it themselves
// (schedule_message).
func withSendPolicy(ctx context.Context, policy string) context.Context {
	return context.WithValue(ctx, sendPolicyKey{}, policy)
}

// sendPolicyFrom returns the policy resolved by the confirmation middleware,
// or confirm (the safe choice) when there is none.
func sendPolicyFrom(ctx context.Context) string {
	if p, ok := ctx.Value(sendPolicyKey{}).(string); ok && store.ValidSendPolicy(p) {
		return p
	}
	return store.SendConfirm
}
