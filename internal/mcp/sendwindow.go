package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/murandido/mcp-wpp/internal/store"
)

// Per-chat send windows (see internal/store/sendwindow.go). The confirmation
// middleware resolves the window after the access check and the send policy,
// like the policy itself, so a hidden chat still answers "chat not found"
// and a chat with policy none is refused before any window logic. Outside
// the window:
//
//   - a message-sending tool (deferrable) becomes a scheduled item for the
//     next opening, still under the send policy: confirm makes a proposal
//     with that send time, direct schedules it at once;
//   - schedule_message moves its send time to the next opening;
//   - any other write aimed at the chat is refused, saying when it opens.
//
// The scheduler checks the window again when an item comes due and moves it
// to the next opening if the window changed meanwhile. Operator schedules
// (`wpp-mcp schedule`, creator operator:cli) ignore windows: they are the
// operator's own intent. Approving a proposal is an operator decision too:
// an immediate proposal approved outside the window is sent at once.

// deferrable lists the message-sending tools the scheduler can run later.
var deferrable = map[string]bool{
	"send_message":       true,
	"send_file":          true,
	"send_audio_message": true,
	"send_reply":         true,
	"send_poll":          true,
	"send_contact_card":  true,
}

// location is the time zone send windows are read in.
func (s *Server) location() *time.Location {
	if s.loc != nil {
		return s.loc
	}
	return time.Local
}

// sendWindowFor returns the send window of the chat ref names, or nil.
func (s *Server) sendWindowFor(ctx context.Context, ref string) (*store.SendWindow, error) {
	if ref == "" || s.client == nil {
		return nil, nil
	}
	return s.client.Store().ChatSendWindow(ctx, s.chatJIDFor(ref))
}

func (s *Server) windowText(w *store.SendWindow) string {
	return fmt.Sprintf("%s %s", w.String(), s.location())
}

// applySendWindow handles a write call aimed at ref outside its send window.
// It returns nil when the call may proceed normally.
func (s *Server) applySendWindow(ctx context.Context, name, ref string, args map[string]any, policy string) *mcp.CallToolResult {
	if ref == "" || name == "schedule_message" {
		return nil // schedule_message adjusts its own send time
	}
	w, err := s.sendWindowFor(ctx, ref)
	if err != nil {
		return mcp.NewToolResultError("cannot read the send window: " + err.Error())
	}
	now := s.clock()
	if w == nil || w.Contains(now, s.location()) {
		return nil
	}
	next := w.NextOpening(now, s.location())
	if !deferrable[name] {
		markAudit(ctx, auditDenied)
		return mcp.NewToolResultError(fmt.Sprintf("%s is outside the send window the user set for %s (%s); nothing was done. The window opens at %s; only messages are deferred automatically, so try this again then.",
			name, ref, s.windowText(w), next.Format(time.RFC3339)))
	}
	return s.deferCall(ctx, name, args, policy, w, next)
}

// deferCall records a message-sending call for the next window opening.
func (s *Server) deferCall(ctx context.Context, name string, args map[string]any, policy string, w *store.SendWindow, next time.Time) *mcp.CallToolResult {
	raw, err := json.Marshal(args)
	if err != nil {
		return mcp.NewToolResultError("cannot record the deferred message: " + err.Error())
	}
	reason := fmt.Sprintf("outside the chat's send window (%s)", s.windowText(w))
	summary := s.summarise(name, args) + "\n  deferred: " + reason
	st := s.client.Store()
	now := s.clock()
	if policy == store.SendDirect {
		p, err := st.ScheduleMessage(ctx, name, string(raw), summary, next, now)
		if err != nil {
			return mcp.NewToolResultError(err.Error())
		}
		s.wakeScheduler()
		res, _ := resultJSON(map[string]any{
			"scheduled_id": p.ID,
			"status":       store.OutboxScheduled,
			"deferred":     true,
			"send_at":      p.SendAt,
			"reason":       reason,
			"next_step":    fmt.Sprintf("Nothing was sent now. It will be sent when the window opens, at send_at. The user can cancel it with `wpp-mcp outbox cancel %d`.", p.ID),
		})
		return res
	}
	p, err := st.CreateDeferredProposal(ctx, name, string(raw), summary, next, now)
	if err != nil {
		return mcp.NewToolResultError(err.Error())
	}
	markAudit(ctx, auditProposed)
	res, _ := resultJSON(map[string]any{
		"proposal_id": p.ID,
		"status":      "awaiting_approval",
		"deferred":    true,
		"send_at":     p.SendAt,
		"expires_at":  p.ExpiresAt,
		"reason":      reason,
		"next_step":   fmt.Sprintf("Nothing was sent. Ask the user to approve with `wpp-mcp outbox approve %d` or on the /outbox page; once approved it is sent when the window opens, at send_at.", p.ID),
	})
	return res
}

// deferIfClosed moves a due scheduled item to the next opening of its
// chat's send window when it is outside it, and reports whether it did.
// Operator schedules are never moved.
func (s *Server) deferIfClosed(ctx context.Context, p store.Proposal, now time.Time) (bool, error) {
	if p.CreatedBy == store.CreatorOperatorCLI {
		return false, nil
	}
	var args map[string]any
	if json.Unmarshal([]byte(p.ArgsJSON), &args) != nil {
		return false, nil // the send path records the corruption
	}
	w, err := s.sendWindowFor(ctx, targetChatRef(p.Tool, args))
	if err != nil || w == nil || w.Contains(now, s.location()) {
		return false, err
	}
	next := w.NextOpening(now, s.location())
	if err := s.client.Store().RescheduleScheduled(ctx, p.ID, next); err != nil {
		if err == store.ErrProposalNotPending {
			return true, nil // cancelled meanwhile; nothing to send
		}
		return false, err
	}
	fmt.Fprintf(os.Stderr, "scheduler: scheduled message #%d is outside its chat's send window; moved to %s\n", p.ID, next.UTC().Format(time.RFC3339))
	return true, nil
}
