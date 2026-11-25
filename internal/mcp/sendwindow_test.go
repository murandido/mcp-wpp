package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/store"
)

// windowServer is scheduleServer with Alice limited to 08:00-22:00 UTC and
// the clock at 23:00 UTC, outside the window.
func windowServer(t *testing.T, confirm bool) (*Server, *store.Store, *fakeClock) {
	t.Helper()
	s, st, clk := scheduleServer(t, confirm)
	s.loc = time.UTC
	clk.set(windowDay.Add(23 * time.Hour))
	if err := st.SetChatSendWindow(context.Background(), visibleJID, "08:00-22:00"); err != nil {
		t.Fatal(err)
	}
	return s, st, clk
}

// windowDay is tomorrow in UTC, not a fixed date: the store expires proposals
// against the real clock, so a fake clock stuck in the past made a deferred
// proposal expire before it could be approved once that date was a week old.
var (
	windowDay   = time.Now().UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	nextOpening = windowDay.Add(32 * time.Hour)
)

type deferredResult struct {
	ProposalID  int64     `json:"proposal_id"`
	ScheduledID int64     `json:"scheduled_id"`
	Status      string    `json:"status"`
	Deferred    bool      `json:"deferred"`
	SendAt      time.Time `json:"send_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Reason      string    `json:"reason"`
}

func decodeDeferred(t *testing.T, res toolResponse) deferredResult {
	t.Helper()
	var out deferredResult
	if err := json.Unmarshal([]byte(res.Text), &out); err != nil || !out.Deferred {
		t.Fatalf("expected a deferred result, got %+v", res)
	}
	return out
}

func TestSendWindow_DeferralFollowsPolicy(t *testing.T) {
	ctx := context.Background()
	send := map[string]any{"recipient": visibleJID, "message": "late"}

	// confirm: a proposal that sends at the next opening once approved.
	s, st, clk := windowServer(t, true)
	out := decodeDeferred(t, callToolDirect(t, s, "send_message", send))
	if out.Status != "awaiting_approval" || !out.SendAt.Equal(nextOpening) || !strings.Contains(out.Reason, "08:00-22:00 UTC") {
		t.Fatalf("confirm: %+v", out)
	}
	if !out.ExpiresAt.After(clk.now()) {
		t.Fatalf("deferred proposal must stay approvable: %+v", out)
	}
	p, err := s.ApproveProposal(ctx, out.ProposalID)
	if err != nil || p.Status != store.OutboxScheduled || p.Tool != "send_message" {
		t.Fatalf("approve deferred: %+v %v", p, err)
	}

	// direct: scheduled at once for the next opening.
	_ = st.SetChatSendPolicy(ctx, visibleJID, store.SendDirect)
	out = decodeDeferred(t, callToolDirect(t, s, "send_message", send))
	if out.Status != store.OutboxScheduled || !out.SendAt.Equal(nextOpening) || out.ScheduledID == 0 {
		t.Fatalf("direct: %+v", out)
	}

	// none: refused as always, before any window logic.
	_ = st.SetChatSendPolicy(ctx, visibleJID, store.SendNone)
	if res := callToolDirect(t, s, "send_message", send); !res.IsError || !strings.Contains(res.Text, `send policy "none"`) {
		t.Fatalf("none: %+v", res)
	}

	// Inside the window nothing is deferred.
	_ = st.SetChatSendPolicy(ctx, visibleJID, store.SendDirect)
	clk.set(windowDay.Add(12 * time.Hour))
	if res := callToolDirect(t, s, "send_message", send); strings.Contains(res.Text, "deferred") || !strings.Contains(res.Text, "Not connected") {
		t.Fatalf("inside the window: %+v", res)
	}
}

func TestSendWindow_OtherWritesRefused(t *testing.T) {
	s, _, _ := windowServer(t, false)
	res := callToolDirect(t, s, "mark_chat_read", map[string]any{"chat_jid": visibleJID})
	if !res.IsError || !strings.Contains(res.Text, "outside the send window") || !strings.Contains(res.Text, nextOpening.Format(time.RFC3339)) {
		t.Fatalf("non-message write outside the window: %+v", res)
	}
}

func TestSendWindow_HiddenChatStaysNotFound(t *testing.T) {
	s, st, _ := windowServer(t, false)
	_ = st.SetChatSendWindow(context.Background(), hiddenJID, "08:00-22:00")
	res := callToolDirect(t, s, "send_message", map[string]any{"recipient": hiddenJID, "message": "x"})
	if !res.IsError || strings.Contains(res.Text, "window") || strings.Contains(res.Text, "deferred") {
		t.Fatalf("hidden chat leaked its window: %+v", res)
	}
	if want := callToolDirect(t, s, "send_message", map[string]any{"recipient": "447700000099@s.whatsapp.net", "message": "x"}); want.Text != strings.ReplaceAll(res.Text, hiddenJID, "447700000099@s.whatsapp.net") {
		t.Fatalf("hidden and nonexistent differ: %q vs %q", res.Text, want.Text)
	}
}

func TestSendWindow_ScheduleMessageMovesToOpening(t *testing.T) {
	s, _, clk := windowServer(t, false)
	at := clk.now().Add(time.Hour) // 00:00, outside
	res := scheduleCall(t, s, visibleJID, at)
	out := decodeDeferred(t, res)
	if out.Status != store.OutboxScheduled || !out.SendAt.Equal(nextOpening) {
		t.Fatalf("schedule outside the window: %+v", out)
	}
	inside := clk.now().Add(10 * time.Hour) // 09:00 next day
	if res := scheduleCall(t, s, visibleJID, inside); strings.Contains(res.Text, "deferred") {
		t.Fatalf("schedule inside the window was moved: %+v", res)
	}
}

func TestSendWindow_SchedulerRechecksAndOperatorIgnores(t *testing.T) {
	ctx := context.Background()
	s, st, clk := scheduleServer(t, false)
	s.loc = time.UTC
	clk.set(windowDay.Add(12 * time.Hour))
	at := windowDay.Add(23 * time.Hour)
	byAI := scheduledID(t, scheduleCall(t, s, visibleJID, at))
	byOperator, err := s.ScheduleMessage(ctx, visibleJID, "operator's own", at)
	if err != nil {
		t.Fatal(err)
	}
	// The window is set after scheduling: at 23:00 the chat is closed.
	_ = st.SetChatSendWindow(ctx, visibleJID, "08:00-22:00")
	clk.set(at.Add(time.Second))
	done, err := s.RunDueScheduled(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(done) != 1 || done[0].ID != byOperator.ID {
		t.Fatalf("only the operator's item is sent (and fails, unpaired): %+v", done)
	}
	moved, _ := st.GetProposal(ctx, byAI)
	if moved.Status != store.OutboxScheduled || moved.SendAt == nil || !moved.SendAt.Equal(nextOpening) {
		t.Fatalf("AI item not moved to the next opening: %+v", moved)
	}
	// At the opening it is sent.
	clk.set(nextOpening.Add(time.Second))
	if done, _ := s.RunDueScheduled(ctx); len(done) != 1 || done[0].ID != byAI {
		t.Fatalf("at the opening: %+v", done)
	}
}

func TestSendWindow_DeferredCallRunsItsTool(t *testing.T) {
	ctx := context.Background()
	s, st, clk := windowServer(t, false)
	out := decodeDeferred(t, callToolDirect(t, s, "send_message", map[string]any{"recipient": visibleJID, "message": "late"}))
	clk.set(nextOpening.Add(time.Second))
	done, err := s.RunDueScheduled(ctx)
	if err != nil || len(done) != 1 || done[0].ID != out.ScheduledID {
		t.Fatalf("deferred call not run: %+v %v", done, err)
	}
	got, _ := st.GetProposal(ctx, out.ScheduledID)
	// It went through send_message's handler; the test daemon is unpaired.
	if got.Status != store.OutboxFailed || !strings.Contains(got.Result, "Not connected") {
		t.Fatalf("deferred call outcome: %+v", got)
	}
}
