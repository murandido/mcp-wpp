package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/store"
)

// fakeClock is a settable clock for the scheduler.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func scheduleServer(t *testing.T, confirm bool) (*Server, *store.Store, *fakeClock) {
	t.Helper()
	s, st := policyServer(t, confirm)
	clk := &fakeClock{t: time.Now().UTC().Truncate(time.Second)}
	s.SetClock(clk.now)
	return s, st, clk
}

func scheduleCall(t *testing.T, s *Server, recipient string, at time.Time) toolResponse {
	t.Helper()
	return callToolDirect(t, s, "schedule_message", map[string]any{"recipient": recipient, "message": "good morning", "send_at": at.Format(time.RFC3339)})
}

func scheduledID(t *testing.T, res toolResponse) int64 {
	t.Helper()
	var out struct {
		ID     int64  `json:"scheduled_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(res.Text), &out); err != nil || out.Status != store.OutboxScheduled {
		t.Fatalf("expected a scheduled item, got %+v", res)
	}
	return out.ID
}

func TestScheduleMessage_ValidatesTime(t *testing.T) {
	s, _, clk := scheduleServer(t, false)
	for _, at := range []string{"tomorrow at 6", "2026-11-16 06:00", "2026-11-16T06:00:00"} {
		res := callToolDirect(t, s, "schedule_message", map[string]any{"recipient": visibleJID, "message": "x", "send_at": at})
		if !res.IsError || !strings.Contains(res.Text, "RFC 3339") {
			t.Errorf("send_at %q: %+v", at, res)
		}
	}
	if res := scheduleCall(t, s, visibleJID, clk.now().Add(-time.Minute)); !res.IsError || !strings.Contains(res.Text, "past") {
		t.Errorf("past time: %+v", res)
	}
	if res := scheduleCall(t, s, visibleJID, clk.now().Add(31*24*time.Hour)); !res.IsError || !strings.Contains(res.Text, "30 days") {
		t.Errorf("too far ahead: %+v", res)
	}
}

func TestScheduleMessage_FollowsSendPolicy(t *testing.T) {
	ctx := context.Background()
	s, st, clk := scheduleServer(t, true)
	at := clk.now().Add(2 * time.Hour)

	// Default (confirm): a proposal that waits until the send time, and
	// once approved becomes scheduled rather than sent.
	res := scheduleCall(t, s, visibleJID, at)
	id := proposalID(t, res)
	p, err := s.ApproveProposal(ctx, id)
	if err != nil || p.Status != store.OutboxScheduled || p.SendAt == nil || !p.SendAt.Equal(at) {
		t.Fatalf("approved scheduled proposal: %+v %v", p, err)
	}
	if got, _ := st.GetProposal(ctx, id); got.Status != store.OutboxScheduled {
		t.Fatalf("stored status: %+v", got)
	}

	_ = st.SetChatSendPolicy(ctx, visibleJID, store.SendDirect)
	scheduledID(t, scheduleCall(t, s, visibleJID, at))

	_ = st.SetChatSendPolicy(ctx, visibleJID, store.SendNone)
	if res := scheduleCall(t, s, visibleJID, at); !res.IsError || !strings.Contains(res.Text, `send policy "none"`) {
		t.Fatalf("none: %+v", res)
	}
}

func TestScheduler_SendsDueItemsOnce(t *testing.T) {
	ctx := context.Background()
	s, st, clk := scheduleServer(t, false)
	start := clk.now()
	early := scheduledID(t, scheduleCall(t, s, visibleJID, start.Add(time.Hour)))
	later := scheduledID(t, scheduleCall(t, s, visibleJID, start.Add(3*time.Hour)))

	if done, err := s.RunDueScheduled(ctx); err != nil || len(done) != 0 {
		t.Fatalf("nothing is due yet: %+v %v", done, err)
	}

	clk.set(start.Add(time.Hour + time.Second))
	done, err := s.RunDueScheduled(ctx)
	if err != nil || len(done) != 1 || done[0].ID != early {
		t.Fatalf("due run: %+v %v", done, err)
	}
	// The test daemon is not connected, so the real send path fails and
	// says why; the failure is recorded.
	got, _ := st.GetProposal(ctx, early)
	if got.Status != store.OutboxFailed || !strings.Contains(got.Result, "Not connected") {
		t.Fatalf("recorded outcome: %+v", got)
	}
	if done, _ := s.RunDueScheduled(ctx); len(done) != 0 {
		t.Fatalf("an item must never be sent twice: %+v", done)
	}
	if got, _ := st.GetProposal(ctx, later); got.Status != store.OutboxScheduled {
		t.Fatalf("the later item must still wait: %+v", got)
	}
}

func TestScheduler_ConcurrentRunsSendOnce(t *testing.T) {
	ctx := context.Background()
	s, _, clk := scheduleServer(t, false)
	scheduledID(t, scheduleCall(t, s, visibleJID, clk.now().Add(time.Minute)))
	clk.set(clk.now().Add(2 * time.Minute))
	var wg sync.WaitGroup
	var mu sync.Mutex
	total := 0
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			done, _ := s.RunDueScheduled(ctx)
			mu.Lock()
			total += len(done)
			mu.Unlock()
		}()
	}
	wg.Wait()
	if total != 1 {
		t.Fatalf("concurrent runs handled the item %d times", total)
	}
}

func TestScheduler_MissedWhileDown(t *testing.T) {
	ctx := context.Background()
	s, st, clk := scheduleServer(t, false)
	start := clk.now()
	late := scheduledID(t, scheduleCall(t, s, visibleJID, start.Add(time.Hour)))
	tooLate := scheduledID(t, scheduleCall(t, s, visibleJID, start.Add(10*time.Minute)))

	// The daemon comes back 1h50 after start: the first item is 50 minutes
	// late and still goes out; the second is 1h40 late and is missed.
	clk.set(start.Add(time.Hour + 50*time.Minute))
	done, err := s.RunDueScheduled(ctx)
	if err != nil || len(done) != 1 || done[0].ID != late {
		t.Fatalf("run after downtime: %+v %v", done, err)
	}
	if got, _ := st.GetProposal(ctx, tooLate); got.Status != store.OutboxMissed {
		t.Fatalf("item more than an hour late: %+v", got)
	}
}

func TestScheduler_RechecksAccessAndPolicy(t *testing.T) {
	ctx := context.Background()
	s, st, clk := scheduleServer(t, false)
	start := clk.now()
	hidden := scheduledID(t, scheduleCall(t, s, visibleJID, start.Add(time.Hour)))
	_ = st.SetChatAccess(ctx, visibleJID, store.AccessDenied, "")
	clk.set(start.Add(time.Hour + time.Second))
	if _, err := s.RunDueScheduled(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetProposal(ctx, hidden); got.Status != store.OutboxFailed || !strings.Contains(got.Result, "chat not found") {
		t.Fatalf("a chat hidden meanwhile must not be sent to: %+v", got)
	}

	_ = st.SetChatAccess(ctx, visibleJID, store.AccessAllowed, "")
	off := scheduledID(t, scheduleCall(t, s, visibleJID, clk.now().Add(time.Hour)))
	_ = st.SetChatSendPolicy(ctx, visibleJID, store.SendNone)
	clk.set(clk.now().Add(time.Hour + time.Second))
	if _, err := s.RunDueScheduled(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetProposal(ctx, off); got.Status != store.OutboxFailed || !strings.Contains(got.Result, `send policy "none"`) {
		t.Fatalf("a chat whose sends were turned off meanwhile: %+v", got)
	}
}

func TestScheduler_CancelledItemIsNotSent(t *testing.T) {
	ctx := context.Background()
	s, st, clk := scheduleServer(t, false)
	id := scheduledID(t, scheduleCall(t, s, visibleJID, clk.now().Add(time.Hour)))
	if err := s.CancelProposal(ctx, id); err != nil {
		t.Fatal(err)
	}
	clk.set(clk.now().Add(2 * time.Hour))
	if done, _ := s.RunDueScheduled(ctx); len(done) != 0 {
		t.Fatalf("cancelled item was sent: %+v", done)
	}
	if got, _ := st.GetProposal(ctx, id); got.Status != store.OutboxCancelled {
		t.Fatalf("status: %+v", got)
	}
}

// RunScheduler wakes at the send time rather than waiting a full interval.
func TestRunScheduler_WakesAtSendTime(t *testing.T) {
	s, st := policyServer(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.RunScheduler(ctx, time.Hour)
	id := scheduledID(t, scheduleCall(t, s, visibleJID, time.Now().Add(2*time.Second)))
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if got, _ := st.GetProposal(ctx, id); got.Status == store.OutboxFailed {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	got, _ := st.GetProposal(ctx, id)
	t.Fatalf("the scheduler did not handle the item at its send time: %+v", got)
}

func TestOperatorSchedule(t *testing.T) {
	ctx := context.Background()
	s, st, clk := scheduleServer(t, true)
	at := clk.now().Add(time.Hour)
	if _, err := s.ScheduleMessage(ctx, "447700000099@s.whatsapp.net", "x", at); err == nil || !strings.Contains(err.Error(), "no cached chat") {
		t.Fatalf("unknown chat: %v", err)
	}
	if _, err := s.ScheduleMessage(ctx, hiddenJID, "x", at); err == nil || !strings.Contains(err.Error(), "hidden") {
		t.Fatalf("hidden chat: %v", err)
	}
	if _, err := s.ScheduleMessage(ctx, visibleJID, "x", clk.now().Add(-time.Minute)); err == nil {
		t.Fatal("past time accepted")
	}
	// Operator schedules need no approval, even when the default is confirm.
	p, err := s.ScheduleMessage(ctx, visibleJID, "wake up", at)
	if err != nil || p.Status != store.OutboxScheduled || !strings.Contains(p.Summary, "operator") || !strings.Contains(p.Summary, "Alice") {
		t.Fatalf("operator schedule: %+v %v", p, err)
	}
	_ = st.SetChatSendPolicy(ctx, visibleJID, store.SendNone)
	if _, err := s.ScheduleMessage(ctx, visibleJID, "x", at); err == nil || !strings.Contains(err.Error(), "none") {
		t.Fatalf("chat with send policy none: %v", err)
	}
	ro := NewReadOnlyServer(s.client, nil, false)
	if _, err := ro.ScheduleMessage(ctx, visibleJID, "x", at); err == nil {
		t.Fatal("a read-only server must not schedule")
	}
	if ro.MCP().GetTool("schedule_message") != nil {
		t.Fatal("schedule_message must not be exposed read-only")
	}
}
