package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/murandido/mcp-wpp/internal/store"
)

// Send confirmation. A write tool aimed at a chat whose send policy is
// "confirm" (the default with -confirm-sends) records a proposal instead of
// acting. The user approves it with `wpp-mcp outbox approve <id>` or on the
// /outbox page, and only then does the daemon run the tool, re-checking chat
// access and the send policy at that moment. A prompt-injected model can
// propose, but never send. See sendpolicy.go for the per-chat policies.

// noConfirm lists write tools whose effects are trivial or only visible to
// the account itself, so confirming each would be noise. A chat whose send
// policy is "none" still refuses them.
var noConfirm = map[string]bool{
	"mark_read":           true,
	"mark_chat_read":      true,
	"send_typing":         true,
	"send_presence":       true,
	"request_chat_access": true,
}

// selfConfirming lists tools that apply the send policy themselves, because
// their proposal is not a plain deferred call (schedule_message records a
// proposal that expires at its send time and, once approved, is scheduled).
var selfConfirming = map[string]bool{
	"schedule_message": true,
}

func needsConfirmation(tool string) bool {
	return !readOnlyToolAccess[tool] && !noConfirm[tool]
}

// confirmMiddleware applies the target chat's send policy to write calls:
// refuse, propose, or act.
func (s *Server) confirmMiddleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name := req.Params.Name
		if s.readOnly || readOnlyToolAccess[name] || executing(ctx) {
			return next(ctx, req)
		}
		args := req.GetArguments()
		ref := targetChatRef(name, args)
		if ref != "" && !s.allowedChat(ctx, ref) {
			// The access middleware has already refused this; repeat it so
			// the send policy of a hidden chat can never leak.
			markAudit(ctx, auditDenied)
			return chatNotFound(ref), nil
		}
		policy, err := s.sendPolicyFor(ctx, ref)
		if err != nil {
			return mcp.NewToolResultError("cannot read the send policy: " + err.Error()), nil
		}
		switch {
		case policy == store.SendNone:
			markAudit(ctx, auditDenied)
			return mcp.NewToolResultError(sendRefusedText(ref)), nil
		case selfConfirming[name]:
			return next(withSendPolicy(ctx, policy), req)
		case policy == store.SendDirect || !needsConfirmation(name):
			return next(ctx, req)
		}
		raw, err := json.Marshal(args)
		if err != nil {
			return mcp.NewToolResultError("cannot record proposal: " + err.Error()), nil
		}
		p, err := s.client.Store().CreateProposal(ctx, name, string(raw), s.summarise(name, args))
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		markAudit(ctx, auditProposed)
		return resultJSON(map[string]any{
			"proposal_id": p.ID,
			"status":      "awaiting_approval",
			"summary":     p.Summary,
			"expires_at":  p.ExpiresAt,
			"next_step":   fmt.Sprintf("Nothing was sent. Ask the user to approve with `wpp-mcp outbox approve %d` or on the /outbox page within 15 minutes.", p.ID),
		})
	}
}

type executingKey struct{}

func executing(ctx context.Context) bool { return ctx.Value(executingKey{}) != nil }

// summarise renders a proposal for the user: the chat by name, the text,
// and any other arguments.
func (s *Server) summarise(tool string, args map[string]any) string {
	var b strings.Builder
	b.WriteString(tool)
	for _, key := range []string{"recipient", "chat_jid"} {
		if v, ok := args[key].(string); ok && v != "" {
			jid := s.chatJIDFor(v)
			name := s.client.Store().FindChatName(jid)
			if name == "" || name == jid {
				fmt.Fprintf(&b, " → %s", jid)
			} else {
				fmt.Fprintf(&b, " → %s (%s)", name, jid)
			}
			break
		}
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		if k != "recipient" && k != "chat_jid" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := fmt.Sprint(args[k])
		if len(v) > 500 {
			v = v[:500] + "…"
		}
		fmt.Fprintf(&b, "\n  %s: %s", k, v)
	}
	return b.String()
}

// ListProposals, ApproveProposal, RejectProposal, CancelProposal and
// ScheduleMessage implement the daemon's Outbox interface.
func (s *Server) ListProposals(ctx context.Context, status string) ([]store.Proposal, error) {
	return s.client.Store().ListProposals(ctx, status)
}

// ApproveProposal executes a pending proposal once and records the outcome.
func (s *Server) ApproveProposal(ctx context.Context, id int64) (store.Proposal, error) {
	st := s.client.Store()
	p, err := st.ClaimProposal(ctx, id)
	if err != nil {
		return store.Proposal{}, err
	}
	finish := func(failed bool, text string) (store.Proposal, error) {
		if err := st.FinishProposal(ctx, id, failed, text); err != nil {
			return *p, err
		}
		p.Result = text
		p.Status = map[bool]string{true: "failed", false: "sent"}[failed]
		return *p, nil
	}
	var args map[string]any
	if err := json.Unmarshal([]byte(p.ArgsJSON), &args); err != nil {
		return finish(true, "corrupt proposal: "+err.Error())
	}
	// The chat may have been hidden, or its sends turned off, since the
	// proposal was made.
	if reason := s.writeBlocked(ctx, p.Tool, args); reason != "" {
		return finish(true, reason)
	}
	if p.SendAt != nil {
		// A scheduled message: approval queued it (status 'scheduled');
		// the scheduler sends it at send_at, checking access again.
		s.wakeScheduler()
		return *p, nil
	}
	tool := s.mcp.GetTool(p.Tool)
	if tool == nil {
		return finish(true, fmt.Sprintf("tool %s is not enabled on this daemon", p.Tool))
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = p.Tool
	req.Params.Arguments = args
	// Run through the access middleware as well, exactly as a direct call.
	res, err := s.accessMiddleware(tool.Handler)(context.WithValue(ctx, executingKey{}, true), req)
	if err != nil {
		return finish(true, err.Error())
	}
	var texts []string
	for _, c := range res.Content {
		if t, ok := c.(mcp.TextContent); ok {
			texts = append(texts, t.Text)
		}
	}
	text := strings.Join(texts, "\n")
	return finish(res.IsError || reportsFailure(text), text)
}

// reportsFailure detects the `{"Success": false, ...}` results several send
// tools return without setting isError.
func reportsFailure(text string) bool {
	var r struct {
		Success *bool `json:"Success"`
	}
	return json.Unmarshal([]byte(text), &r) == nil && r.Success != nil && !*r.Success
}

// RejectProposal discards a pending proposal.
func (s *Server) RejectProposal(ctx context.Context, id int64) error {
	return s.client.Store().RejectProposal(ctx, id)
}

// CancelProposal withdraws a pending proposal or a scheduled message.
func (s *Server) CancelProposal(ctx context.Context, id int64) error {
	return s.client.Store().CancelProposal(ctx, id)
}
