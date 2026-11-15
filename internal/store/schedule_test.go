package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func openFileStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSendPolicy_SetGetReset(t *testing.T) {
	s := openFileStore(t)
	ctx := context.Background()
	if p, err := s.ChatSendPolicy(ctx, aliceJID); err != nil || p != SendDefault {
		t.Fatalf("no policy yet: %q %v", p, err)
	}
	for _, p := range []string{SendNone, SendConfirm, SendDirect} {
		if err := s.SetChatSendPolicy(ctx, aliceJID, p); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.ChatSendPolicy(ctx, aliceJID); got != p {
			t.Fatalf("policy = %q, want %q", got, p)
		}
	}
	if err := s.SetChatSendPolicy(ctx, aliceJID, "sometimes"); err == nil {
		t.Fatal("unknown policy accepted")
	}
	if err := s.SetChatSendPolicy(ctx, "", SendNone); err == nil {
		t.Fatal("empty JID accepted")
	}
	if err := s.SetChatSendPolicy(ctx, aliceJID, "reset"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ChatSendPolicy(ctx, aliceJID); got != SendDefault {
		t.Fatalf("after reset: %q", got)
	}
}

func TestSendPolicy_IndependentOfReadDecision(t *testing.T) {
	s := openFileStore(t)
	ctx := context.Background()
	if err := s.StoreChat(aliceJID, "Alice", time.Now()); err != nil {
		t.Fatal(err)
	}
	// A send decision alone does not make the chat visible.
	if err := s.SetChatSendPolicy(ctx, aliceJID, SendDirect); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ChatAllowed(ctx, aliceJID); ok {
		t.Fatal("a send policy must not widen visibility")
	}
	if err := s.SetChatAccess(ctx, aliceJID, AccessAllowed, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SetChatAccess(ctx, aliceJID, AccessDefault, ""); err != nil {
		t.Fatal(err)
	}
	entries, err := s.ListAccess(ctx, "Alice", 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("list: %+v %v", entries, err)
	}
	if entries[0].Send != SendDirect || entries[0].State != AccessDefault {
		t.Fatalf("resetting the read decision must keep the send policy: %+v", entries[0])
	}
}

func TestValidateSendAt(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		at time.Time
		ok bool
	}{
		{now.Add(-time.Second), false},
		{now, false},
		{now.Add(time.Minute), true},
		{now.Add(MaxScheduleAhead), true},
		{now.Add(MaxScheduleAhead + time.Second), false},
	} {
		err := ValidateSendAt(tc.at, now)
		if (err == nil) != tc.ok {
			t.Errorf("ValidateSendAt(%s) = %v, want ok=%v", tc.at, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrScheduleTime) {
			t.Errorf("error does not wrap ErrScheduleTime: %v", err)
		}
	}
}

func TestSchedule_DueClaimOnceAndMissed(t *testing.T) {
	s := openFileStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	a, err := s.ScheduleMessage(ctx, "schedule_message", `{"recipient":"x","message":"a"}`, "a", now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.ScheduleMessage(ctx, "schedule_message", `{"recipient":"x","message":"b"}`, "b", now.Add(2*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != OutboxScheduled || a.SendAt == nil {
		t.Fatalf("scheduled item: %+v", a)
	}
	if _, err := s.ScheduleMessage(ctx, "schedule_message", "{}", "past", now.Add(-time.Minute), now); err == nil {
		t.Fatal("a past time was scheduled")
	}

	if next, err := s.NextScheduledAt(ctx); err != nil || next == nil || !next.Equal(a.SendAt.UTC()) {
		t.Fatalf("next send time: %v %v", next, err)
	}
	if due, _ := s.DueScheduled(ctx, now.Add(30*time.Minute)); len(due) != 0 {
		t.Fatalf("nothing is due yet: %+v", due)
	}
	if _, err := s.ClaimScheduled(ctx, a.ID, now.Add(30*time.Minute)); !errors.Is(err, ErrProposalNotPending) {
		t.Fatalf("claiming an item before its time: %v", err)
	}

	at := now.Add(time.Hour + time.Second)
	due, err := s.DueScheduled(ctx, at)
	if err != nil || len(due) != 1 || due[0].ID != a.ID {
		t.Fatalf("due at +1h: %+v %v", due, err)
	}
	if _, err := s.ClaimScheduled(ctx, a.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimScheduled(ctx, a.ID, at); !errors.Is(err, ErrProposalNotPending) {
		t.Fatalf("second claim must fail: %v", err)
	}
	if err := s.FinishProposal(ctx, a.ID, false, "ok"); err != nil {
		t.Fatal(err)
	}

	// b comes due at +2h; at +3h01 the daemon was down too long.
	n, err := s.MarkMissedScheduled(ctx, now.Add(3*time.Hour+time.Minute), MaxSendDelay)
	if err != nil || n != 1 {
		t.Fatalf("missed: %d %v", n, err)
	}
	got, err := s.GetProposal(ctx, b.ID)
	if err != nil || got.Status != OutboxMissed || !strings.Contains(got.Result, "not sent") {
		t.Fatalf("missed item: %+v %v", got, err)
	}
	if got, _ := s.GetProposal(ctx, a.ID); got.Status != OutboxSent {
		t.Fatalf("sent item changed: %+v", got)
	}
}

func TestSchedule_LateButWithinGraceIsDue(t *testing.T) {
	s := openFileStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	p, _ := s.ScheduleMessage(ctx, "schedule_message", "{}", "x", now.Add(time.Minute), now)
	at := now.Add(time.Minute + 59*time.Minute)
	if n, _ := s.MarkMissedScheduled(ctx, at, MaxSendDelay); n != 0 {
		t.Fatal("an item 59 minutes late must still be sent")
	}
	if due, _ := s.DueScheduled(ctx, at); len(due) != 1 || due[0].ID != p.ID {
		t.Fatalf("due: %+v", due)
	}
}

func TestSchedule_ProposalApprovalSchedules(t *testing.T) {
	s := openFileStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	sendAt := now.Add(3 * time.Hour)
	p, err := s.CreateScheduledProposal(ctx, "schedule_message", "{}", "x", sendAt, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != OutboxPending || !p.ExpiresAt.Equal(sendAt.Truncate(time.Second)) {
		t.Fatalf("a scheduled proposal waits until its send time: %+v", p)
	}
	if due, _ := s.DueScheduled(ctx, sendAt.Add(time.Second)); len(due) != 0 {
		t.Fatal("an unapproved proposal must never be due")
	}
	claimed, err := s.ClaimProposal(ctx, p.ID)
	if err != nil || claimed.Status != OutboxScheduled {
		t.Fatalf("approval: %+v %v", claimed, err)
	}
	if due, _ := s.DueScheduled(ctx, sendAt.Add(time.Second)); len(due) != 1 {
		t.Fatal("an approved proposal is due at its send time")
	}
	list, err := s.ListProposals(ctx, OutboxPending+","+OutboxScheduled)
	if err != nil || len(list) != 1 || list[0].SendAt == nil {
		t.Fatalf("list pending,scheduled: %+v %v", list, err)
	}
}

func TestSchedule_Cancel(t *testing.T) {
	s := openFileStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	sch, _ := s.ScheduleMessage(ctx, "schedule_message", "{}", "x", now.Add(time.Hour), now)
	prop, _ := s.CreateProposal(ctx, "send_message", "{}", "y")
	for _, id := range []int64{sch.ID, prop.ID} {
		if err := s.CancelProposal(ctx, id); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.GetProposal(ctx, id); got.Status != OutboxCancelled {
			t.Fatalf("cancelled item: %+v", got)
		}
		if err := s.CancelProposal(ctx, id); err == nil {
			t.Fatal("cancelling twice must fail")
		}
	}
	if due, _ := s.DueScheduled(ctx, now.Add(2*time.Hour)); len(due) != 0 {
		t.Fatal("a cancelled item must not be due")
	}
	if _, err := s.GetProposal(ctx, 9999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing item: %v", err)
	}
}

func TestSchedule_QueueIsBounded(t *testing.T) {
	s := openFileStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < maxScheduled; i++ {
		if _, err := s.ScheduleMessage(ctx, "schedule_message", "{}", "x", now.Add(time.Hour), now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ScheduleMessage(ctx, "schedule_message", "{}", "x", now.Add(time.Hour), now); err == nil {
		t.Fatal("the scheduled queue must be bounded")
	}
}

// An outbox created before scheduling existed is rebuilt with send_at and
// the new statuses, keeping its rows.
func TestMigrateOutbox_FromV1(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		"DROP TABLE outbox",
		`CREATE TABLE outbox (
			id INTEGER PRIMARY KEY AUTOINCREMENT, tool TEXT NOT NULL, args_json TEXT NOT NULL, summary TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed', 'rejected', 'expired')),
			result TEXT, created_at TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL, decided_at TIMESTAMP)`,
		"INSERT INTO outbox (id, tool, args_json, summary, status, result, created_at, expires_at) VALUES (7, 'send_message', '{}', 'old', 'sent', 'ok', '2026-01-01 10:00:00+00:00', '2026-01-01 10:15:00+00:00')",
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	s.Close()

	s, err = Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	ctx := context.Background()
	old, err := s.GetProposal(ctx, 7)
	if err != nil || old.Summary != "old" || old.Status != OutboxSent || old.Result != "ok" || old.SendAt != nil {
		t.Fatalf("old row after migration: %+v %v", old, err)
	}
	now := time.Now().UTC()
	p, err := s.ScheduleMessage(ctx, "schedule_message", "{}", "new", now.Add(time.Hour), now)
	if err != nil || p.ID <= 7 {
		t.Fatalf("schedule after migration: %+v %v", p, err)
	}
	// Running the migration again is a no-op.
	if err := migrateOutbox(s.db); err != nil {
		t.Fatal(err)
	}
}
