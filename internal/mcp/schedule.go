package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/murandido/mcp-wpp/internal/store"
)

// Scheduled messages. schedule_message records a text message the daemon
// sends at a future time, so no external routine or temporary send window
// is needed. It follows the target chat's send policy when it is created
// (none refuses, confirm proposes, direct schedules), and the scheduler
// re-checks access and the policy when it sends. Scheduling exists only in
// -write mode: the tool is not exposed read-only, and serve starts the
// scheduler only with -write. Items live in the encrypted outbox table, so
// they survive restarts; see internal/store/schedule.go for their lifecycle.

// SchedulerInterval is the longest the scheduler sleeps between checks. It
// also wakes at the next send time and whenever a message is scheduled.
const SchedulerInterval = 15 * time.Second

// minSchedulerWait keeps the scheduler from spinning while due items wait
// for a connection.
const minSchedulerWait = time.Second

type scheduleMessageArgs struct {
	Recipient string `json:"recipient"`
	Message   string `json:"message"`
	SendAt    string `json:"send_at"`
}

func (s *Server) registerScheduleMessage() {
	tool := mcp.NewTool("schedule_message",
		mcp.WithDescription("Schedule a WhatsApp text message for the daemon to send at a future time (at most 30 days ahead); nothing is sent now. Depending on the chat's send policy the user must first approve it (returns `{proposal_id, status: \"awaiting_approval\", send_at}`) or it is scheduled at once (returns `{scheduled_id, status: \"scheduled\", send_at}`); a send_at outside the chat's send window moves to its next opening (`deferred: true`); the user can cancel it with `wpp-mcp outbox cancel <id>` until it is sent. Use send_message to send right away."),
		mcp.WithString("recipient", mcp.Required(), mcp.Description(recipientDesc)),
		mcp.WithString("message", mcp.Required(), mcp.Description("message body text")),
		mcp.WithString("send_at", mcp.Required(), mcp.Description("when to send, RFC 3339 with a UTC offset, e.g. `2026-11-16T06:00:00-03:00`; must be in the future and at most 30 days ahead")),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
	)
	s.mcp.AddTool(tool, mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a scheduleMessageArgs) (*mcp.CallToolResult, error) {
		if strings.TrimSpace(a.Recipient) == "" || a.Message == "" || a.SendAt == "" {
			return mcp.NewToolResultError("recipient, message and send_at are required"), nil
		}
		sendAt, err := time.Parse(time.RFC3339, strings.TrimSpace(a.SendAt))
		if err != nil {
			return mcp.NewToolResultError("send_at must be RFC 3339 with a UTC offset, e.g. 2026-11-16T06:00:00-03:00"), nil
		}
		now := s.clock()
		if err := store.ValidateSendAt(sendAt, now); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		// A send time outside the chat's send window moves to its next
		// opening.
		var windowNote string
		if w, err := s.sendWindowFor(ctx, a.Recipient); err != nil {
			return mcp.NewToolResultError("cannot read the send window: " + err.Error()), nil
		} else if w != nil && !w.Contains(sendAt, s.location()) {
			sendAt = w.NextOpening(sendAt, s.location())
			windowNote = fmt.Sprintf("send_at was outside the chat's send window (%s) and was moved to its next opening", s.windowText(w))
		}
		args := map[string]any{"recipient": a.Recipient, "message": a.Message, "send_at": sendAt.Format(time.RFC3339)}
		raw, _ := json.Marshal(args)
		summary := s.summarise("schedule_message", args)
		st := s.client.Store()
		if sendPolicyFrom(ctx) == store.SendDirect {
			p, err := st.ScheduleMessage(ctx, "schedule_message", string(raw), summary, sendAt, now)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			s.wakeScheduler()
			return resultJSON(withNote(map[string]any{
				"scheduled_id": p.ID,
				"status":       store.OutboxScheduled,
				"send_at":      p.SendAt,
				"summary":      p.Summary,
				"next_step":    fmt.Sprintf("It will be sent at send_at. The user can cancel it with `wpp-mcp outbox cancel %d`.", p.ID),
			}, windowNote))
		}
		p, err := st.CreateScheduledProposal(ctx, "schedule_message", string(raw), summary, sendAt, now)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return resultJSON(withNote(map[string]any{
			"proposal_id": p.ID,
			"status":      "awaiting_approval",
			"send_at":     p.SendAt,
			"expires_at":  p.ExpiresAt,
			"summary":     p.Summary,
			"next_step":   fmt.Sprintf("Nothing is scheduled yet. Ask the user to approve with `wpp-mcp outbox approve %d` or on the /outbox page before the send time.", p.ID),
		}, windowNote))
	}))
}

// withNote adds a deferral note to a result, when there is one.
func withNote(m map[string]any, note string) map[string]any {
	if note != "" {
		m["deferred"] = true
		m["reason"] = note
	}
	return m
}

// ScheduleMessage schedules a text message on the operator's behalf
// (`wpp-mcp schedule`). Operator actions need no approval, but the chat must
// exist, be visible and allow sends, because the scheduler applies the same
// checks when it sends.
func (s *Server) ScheduleMessage(ctx context.Context, ref, message string, sendAt time.Time) (store.Proposal, error) {
	if s.readOnly {
		return store.Proposal{}, errors.New("scheduling needs a daemon started with -write")
	}
	jid := s.chatJIDFor(ref)
	if jid == "" || message == "" {
		return store.Proposal{}, errors.New("a chat and a message are required")
	}
	st := s.client.Store()
	if c, err := st.GetChat(ctx, jid, false); err != nil || c == nil {
		return store.Proposal{}, fmt.Errorf("no cached chat %s; pass the JID of an existing chat (see `wpp-mcp access list`)", jid)
	}
	if !s.allowedChat(ctx, jid) {
		return store.Proposal{}, fmt.Errorf("chat %s is hidden by the access policy, and scheduled messages are only sent to visible chats; allow it first with `wpp-mcp access allow %s`", jid, jid)
	}
	if policy, err := s.sendPolicyFor(ctx, jid); err != nil {
		return store.Proposal{}, err
	} else if policy == store.SendNone {
		return store.Proposal{}, fmt.Errorf("chat %s has send policy \"none\"; change it first with `wpp-mcp access send %s confirm`", jid, jid)
	}
	args := map[string]any{"recipient": jid, "message": message, "send_at": sendAt.Format(time.RFC3339)}
	raw, _ := json.Marshal(args)
	summary := s.summarise("schedule_message", args)
	p, err := st.ScheduleMessage(store.WithCreator(ctx, store.CreatorOperatorCLI), "schedule_message", string(raw), summary, sendAt, s.clock())
	if err != nil {
		return store.Proposal{}, err
	}
	s.wakeScheduler()
	return *p, nil
}

// RunScheduler sends due scheduled messages until ctx ends. It checks at
// least every interval, at the next send time, and when a message is
// scheduled. serve runs it only in -write mode.
func (s *Server) RunScheduler(ctx context.Context, interval time.Duration) {
	for {
		if _, err := s.RunDueScheduled(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "scheduler: %v\n", err)
		}
		wait := interval
		if next, err := s.client.Store().NextScheduledAt(ctx); err == nil && next != nil {
			if d := next.Sub(s.clock()); d < wait {
				wait = d
			}
		}
		wait = max(wait, minSchedulerWait)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-s.schedWake:
		case <-timer.C:
		}
		timer.Stop()
	}
}

// wakeScheduler nudges RunScheduler after a message is scheduled.
func (s *Server) wakeScheduler() {
	select {
	case s.schedWake <- struct{}{}:
	default:
	}
}

// RunDueScheduled processes the scheduled messages that are due now, once,
// and returns the items it finished (sent or failed). Items more than
// store.MaxSendDelay late (the daemon was down) are marked missed. While the
// account is paired but momentarily disconnected, due items wait for the
// connection instead of failing, until they become missed.
func (s *Server) RunDueScheduled(ctx context.Context) ([]store.Proposal, error) {
	if s.client == nil {
		return nil, nil
	}
	st := s.client.Store()
	now := s.clock()
	if n, err := st.MarkMissedScheduled(ctx, now, store.MaxSendDelay); err != nil {
		return nil, err
	} else if n > 0 {
		fmt.Fprintf(os.Stderr, "scheduler: %d scheduled message(s) missed their send time\n", n)
	}
	if s.client.IsLoggedIn() && !s.client.IsConnected() {
		return nil, nil
	}
	due, err := st.DueScheduled(ctx, now)
	if err != nil {
		return nil, err
	}
	var done []store.Proposal
	for _, item := range due {
		// The chat's send window may have changed since it was scheduled.
		if moved, err := s.deferIfClosed(ctx, item, now); err != nil {
			return done, err
		} else if moved {
			continue
		}
		p, err := st.ClaimScheduled(ctx, item.ID, now)
		if errors.Is(err, store.ErrProposalNotPending) {
			continue // cancelled or taken meanwhile
		}
		if err != nil {
			return done, err
		}
		failed, text := s.sendScheduled(ctx, p)
		if err := st.FinishProposal(ctx, p.ID, failed, text); err != nil {
			return done, err
		}
		p.Status, p.Result = map[bool]string{true: store.OutboxFailed, false: store.OutboxSent}[failed], text
		fmt.Fprintf(os.Stderr, "scheduler: scheduled message #%d %s\n", p.ID, p.Status)
		done = append(done, *p)
	}
	return done, nil
}

// sendScheduled sends one claimed item through the normal send path (rate
// limiter included), after checking that its chat is still visible and
// still allows sends. A schedule_message item is a plain text send; a call
// deferred by a send window runs its tool as an approved proposal would.
func (s *Server) sendScheduled(ctx context.Context, p *store.Proposal) (failed bool, result string) {
	var args map[string]any
	if err := json.Unmarshal([]byte(p.ArgsJSON), &args); err != nil {
		return true, "corrupt scheduled message: " + err.Error()
	}
	if reason := s.creatorBlocked(ctx, p); reason != "" {
		return true, reason
	}
	if reason := s.writeBlocked(ctx, p.Tool, args); reason != "" {
		return true, reason
	}
	if p.Tool != "schedule_message" {
		return s.execute(ctx, p.Tool, args)
	}
	recipient, _ := args["recipient"].(string)
	message, _ := args["message"].(string)
	r := s.client.Send(ctx, recipient, message)
	raw, err := json.Marshal(r)
	if err != nil {
		return true, err.Error()
	}
	return !r.Success, string(raw)
}
