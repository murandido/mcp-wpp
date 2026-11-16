package mcp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/murandido/mcp-wpp/internal/auth"
	"github.com/murandido/mcp-wpp/internal/client"
	"github.com/murandido/mcp-wpp/internal/store"
)

// Approving outbox proposals from the WhatsApp self chat (serve
// -self-approve, which needs -write). The operator types into their own
// "Message yourself" chat on the phone:
//
//	outbox         list what awaits approval
//	approve <id>   the same as `wpp-mcp outbox approve <id>`
//	reject <id>    the same as `wpp-mcp outbox reject <id>`
//
// internal/client decides which messages qualify (live, own chat, from the
// account, from another device than this daemon's, recent; see
// selfCommandOf). Approval goes through ApproveProposal, so it re-runs the
// access middleware and the send policy and claims the proposal atomically,
// exactly as the CLI does. Every decision is audited as SelfApproveActor,
// without message text. While self-approval is on, MCP write tools may not
// target the account's own chat, so a model can neither fake a command nor
// clutter the command channel.

// SelfApproveActor is the audit actor of self-chat decisions.
const SelfApproveActor = "operator:whatsapp"

// maxSelfListed bounds the `outbox` reply.
const maxSelfListed = 10

// EnableSelfApprove turns on self-chat approval and the own-chat guard.
func (s *Server) EnableSelfApprove() { s.selfApprove = true }

// isOwnChat reports whether ref names the account's own chat.
func (s *Server) isOwnChat(ref string) bool {
	if s.client == nil || ref == "" {
		return false
	}
	jid := s.chatJIDFor(ref)
	owns := s.client.OwnChatJIDs
	if s.ownChats != nil {
		owns = s.ownChats
	}
	for _, own := range owns() {
		if jid == own || strings.TrimSpace(ref) == own {
			return true
		}
	}
	return false
}

// ownChatBlocked returns the refusal for a write to the own chat while
// self-approval is on, or "".
func (s *Server) ownChatBlocked(ref string) string {
	if !s.selfApprove || !s.isOwnChat(ref) {
		return ""
	}
	return "writing to the account's own chat is disabled while approval from the self chat is on (serve -self-approve); nothing was done"
}

// HandleSelfCommand runs one self-chat command and returns the reply to post
// in the self chat ("" when the text is not a command, or the command was
// rejected and nothing should be said).
func (s *Server) HandleSelfCommand(ctx context.Context, cmd client.SelfCommand) string {
	if !s.selfApprove || s.readOnly || s.client == nil {
		return ""
	}
	verb, id, ok := parseSelfCommand(cmd.Text)
	if !ok {
		return ""
	}
	action := "selfchat " + verb
	if cmd.Rejected != "" {
		// Written by this daemon (or delivered too late): never acts.
		s.auditSelf(ctx, action, id, "", store.OutcomeDenied, "rejected="+strings.ReplaceAll(cmd.Rejected, " ", "_"))
		fmt.Fprintf(os.Stderr, "self-approve: ignored a %q command (%s)\n", verb, cmd.Rejected)
		return ""
	}
	ctx = auth.WithIdentity(ctx, auth.Operator("whatsapp"))
	switch verb {
	case "outbox":
		ps, err := s.ListProposals(ctx, store.OutboxPending)
		if err != nil {
			s.auditSelf(ctx, action, 0, "", store.OutcomeError, "")
			return "outbox: " + err.Error()
		}
		s.auditSelf(ctx, action, 0, "", store.OutcomeOK, "")
		return selfOutboxText(ps)
	case "reject":
		p, _ := s.client.Store().GetProposal(ctx, id)
		creator := ""
		if p != nil {
			creator = p.CreatedBy
		}
		if err := s.RejectProposal(ctx, id); err != nil {
			s.auditSelf(ctx, action, id, creator, store.OutcomeError, "")
			return fmt.Sprintf("#%d: not rejected (%s)", id, selfErr(err))
		}
		s.auditSelf(ctx, action, id, creator, store.OutcomeOK, "")
		return fmt.Sprintf("#%d: rejected", id)
	default: // approve
		p, err := s.ApproveProposal(ctx, id)
		if err != nil {
			s.auditSelf(ctx, action, id, "", store.OutcomeError, "")
			return fmt.Sprintf("#%d: not approved (%s)", id, selfErr(err))
		}
		outcome := store.OutcomeOK
		if p.Status == store.OutboxFailed {
			outcome = store.OutcomeError
		}
		s.auditSelf(ctx, action, id, p.CreatedBy, outcome, "")
		switch {
		case p.Status == store.OutboxScheduled && p.SendAt != nil:
			return fmt.Sprintf("#%d: approved, scheduled for %s", id, p.SendAt.In(s.location()).Format("2006-01-02 15:04 MST"))
		case p.Status == store.OutboxFailed:
			return fmt.Sprintf("#%d: failed: %s", id, truncate(p.Result, 200))
		}
		return fmt.Sprintf("#%d: %s", id, p.Status)
	}
}

// parseSelfCommand recognises "outbox", "approve <id>" and "reject <id>"
// (case-insensitive, an optional '#' before the id). Anything else is a
// note to self and is ignored.
func parseSelfCommand(text string) (verb string, id int64, ok bool) {
	f := strings.Fields(strings.ToLower(strings.TrimSpace(text)))
	switch {
	case len(f) == 1 && f[0] == "outbox":
		return "outbox", 0, true
	case len(f) == 2 && (f[0] == "approve" || f[0] == "reject"):
		n, err := strconv.ParseInt(strings.TrimPrefix(f[1], "#"), 10, 64)
		if err != nil || n <= 0 {
			return "", 0, false
		}
		return f[0], n, true
	}
	return "", 0, false
}

func selfOutboxText(ps []store.Proposal) string {
	if len(ps) == 0 {
		return "outbox: nothing awaits approval"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "outbox: %d awaiting approval", len(ps))
	for i, p := range ps {
		if i == maxSelfListed {
			fmt.Fprintf(&b, "\n… and %d more (wpp-mcp outbox)", len(ps)-i)
			break
		}
		by := p.CreatedBy
		if by == "" {
			by = "unknown"
		}
		fmt.Fprintf(&b, "\n\n#%d by %s\n%s", p.ID, by, truncate(p.Summary, 300))
	}
	b.WriteString("\n\nReply `approve <id>` or `reject <id>`.")
	return b.String()
}

func selfErr(err error) string {
	if errors.Is(err, store.ErrProposalNotPending) {
		return "it is not pending: already decided, expired or unknown"
	}
	return err.Error()
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// auditSelf records a self-chat decision: the command, the proposal id and
// its creator, never message text.
func (s *Server) auditSelf(ctx context.Context, action string, id int64, creator, outcome, extra string) {
	if s.auditor == nil {
		return
	}
	var detail []string
	if id != 0 {
		detail = append(detail, "id="+strconv.FormatInt(id, 10))
	}
	if creator != "" {
		detail = append(detail, "creator="+creator)
	}
	if extra != "" {
		detail = append(detail, extra)
	}
	_ = s.auditor.RecordAudit(context.WithoutCancel(ctx), store.AuditEntry{
		At:      time.Now().UTC(),
		Actor:   SelfApproveActor,
		Kind:    store.AuditAdmin,
		Action:  action,
		Detail:  strings.Join(detail, " "),
		Outcome: outcome,
	})
}

// RunSelfCommand handles cmd and posts the reply in the self chat. serve
// calls it in its own goroutine for every qualifying message.
func (s *Server) RunSelfCommand(ctx context.Context, cmd client.SelfCommand) {
	reply := s.HandleSelfCommand(ctx, cmd)
	if reply == "" {
		return
	}
	if r := s.client.Send(ctx, cmd.ChatJID, reply); !r.Success {
		fmt.Fprintf(os.Stderr, "self-approve: could not reply in the self chat: %s\n", r.Message)
	}
}
