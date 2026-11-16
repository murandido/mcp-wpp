package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/auth"
)

// notesFixture is a full store with three chats (a and b allowed, c hidden)
// and messages one minute apart in a.
func notesFixture(t *testing.T) (*Store, string, string, string) {
	t.Helper()
	st := openFileStore(t)
	ctx := context.Background()
	a, b, c := "447700000001@s.whatsapp.net", "447700000002@s.whatsapp.net", "447700000003@s.whatsapp.net"
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	for _, jid := range []string{a, b, c} {
		if err := st.StoreChat(jid, "chat "+jid[:12], base); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i <= 5; i++ {
		m := Message{ID: fmt.Sprintf("m%d", i), ChatJID: a, Sender: a, Content: fmt.Sprintf("message %d", i), Timestamp: base.Add(time.Duration(i) * time.Minute)}
		if err := st.StoreMessage(ctx, m, nil, nil, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.StoreMessage(ctx, Message{ID: "x1", ChatJID: b, Sender: b, Content: "other chat", Timestamp: base}, nil, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	for _, jid := range []string{a, b} {
		if err := st.SetChatAccess(ctx, jid, AccessAllowed, ""); err != nil {
			t.Fatal(err)
		}
	}
	return st, a, b, c
}

func msgIDs(msgs []Message) string {
	var out []string
	for _, m := range msgs {
		out = append(out, m.ID)
	}
	return strings.Join(out, ",")
}

func TestChatNotes_GrowWithEachUpdate(t *testing.T) {
	st, a, _, _ := notesFixture(t)
	view := st.Scoped()
	ctx := auth.WithIdentity(context.Background(), auth.Identity{Kind: auth.KindToken, Name: "claude-ai", TokenID: 7})

	n, err := view.GetChatNotes(ctx, a)
	if err != nil || n.Version != 0 || n.Summary != "" {
		t.Fatalf("first read: %+v %v", n, err)
	}
	// Without a watermark the newest messages come back, oldest first.
	msgs, more, err := view.MessagesAfterNotes(ctx, n, 3)
	if err != nil || msgIDs(msgs) != "m3,m4,m5" || !more {
		t.Fatalf("first page: %s more=%v %v", msgIDs(msgs), more, err)
	}

	n, err = view.UpdateChatNotes(ctx, a, "Alice: likes tea.", "m3", 0)
	if err != nil || n.Version != 1 || n.UpdatedBy != "token:claude-ai" || n.CoveredUntilID != "m3" {
		t.Fatalf("update 1: %+v %v", n, err)
	}
	if msgs, more, _ = view.MessagesAfterNotes(ctx, n, 10); msgIDs(msgs) != "m4,m5" || more {
		t.Fatalf("after m3: %s more=%v", msgIDs(msgs), more)
	}

	// A stale version is refused, so parallel conversations never overwrite
	// each other.
	if _, err := view.UpdateChatNotes(ctx, a, "stale", "m5", 0); !errors.Is(err, ErrNotesConflict) {
		t.Fatalf("stale update: %v", err)
	}
	// The watermark never moves back.
	n, err = view.UpdateChatNotes(ctx, a, "Alice: likes tea. Birthday in May.", "m2", 1)
	if err != nil || n.Version != 2 || n.CoveredUntilID != "m3" {
		t.Fatalf("update 2: %+v %v", n, err)
	}
	got, _ := view.GetChatNotes(ctx, a)
	if got.Summary != "Alice: likes tea. Birthday in May." || got.Version != 2 || got.CoveredUntilID != "m3" {
		t.Fatalf("read back: %+v", got)
	}
	hist, err := view.ChatNotesHistory(ctx, a)
	if err != nil || len(hist) != 1 || hist[0].Version != 1 || hist[0].Summary != "Alice: likes tea." {
		t.Fatalf("history: %+v %v", hist, err)
	}
	// Revert makes v1 current again as v3.
	n, err = view.RevertChatNotes(ctx, a, 1)
	if err != nil || n.Version != 3 || n.Summary != "Alice: likes tea." {
		t.Fatalf("revert: %+v %v", n, err)
	}
}

func TestChatNotes_Validation(t *testing.T) {
	st, a, _, _ := notesFixture(t)
	ctx := context.Background()
	if _, err := st.UpdateChatNotes(ctx, a, "  ", "", 0); err == nil {
		t.Fatal("empty summary accepted")
	}
	if _, err := st.UpdateChatNotes(ctx, a, strings.Repeat("x", MaxNotesBytes+1), "", 0); err == nil {
		t.Fatal("oversized summary accepted")
	}
	// A message of another chat is not a valid watermark.
	if _, err := st.UpdateChatNotes(ctx, a, "notes", "x1", 0); !errors.Is(err, ErrMessageNotFound) {
		t.Fatalf("foreign watermark: %v", err)
	}
	if _, err := st.UpdateChatNotes(ctx, "", "notes", "", 0); err == nil {
		t.Fatal("missing jid accepted")
	}
}

func TestChatNotes_HistoryIsBounded(t *testing.T) {
	st, a, _, _ := notesFixture(t)
	ctx := context.Background()
	for v := 0; v < notesHistoryKeep+5; v++ {
		if _, err := st.UpdateChatNotes(ctx, a, fmt.Sprintf("v%d", v+1), "", v); err != nil {
			t.Fatal(err)
		}
	}
	hist, _ := st.ChatNotesHistory(ctx, a)
	if len(hist) != notesHistoryKeep || hist[0].Version != notesHistoryKeep+4 {
		t.Fatalf("history: %d entries, newest %d", len(hist), hist[0].Version)
	}
}

// Hidden chats, and chats outside a token's set, behave as if they did not
// exist; the notes never leak.
func TestChatNotes_Scoped(t *testing.T) {
	st, a, b, c := notesFixture(t)
	ctx := context.Background()
	for _, jid := range []string{a, b, c} {
		if _, err := st.UpdateChatNotes(ctx, jid, "secret about "+jid, "", 0); err != nil {
			t.Fatal(err)
		}
	}
	view := st.Scoped()
	if _, err := view.GetChatNotes(ctx, c); !errors.Is(err, ErrChatNotFound) {
		t.Fatalf("hidden chat: %v", err)
	}
	if _, err := view.GetChatNotes(ctx, "999@s.whatsapp.net"); !errors.Is(err, ErrChatNotFound) {
		t.Fatalf("unknown chat: %v", err)
	}
	if _, err := view.UpdateChatNotes(ctx, c, "overwrite", "", 1); !errors.Is(err, ErrChatNotFound) {
		t.Fatalf("hidden update: %v", err)
	}
	if _, err := view.ChatNotesHistory(ctx, c); !errors.Is(err, ErrChatNotFound) {
		t.Fatalf("hidden history: %v", err)
	}
	tok := st.ScopedTo([]string{b})
	if _, err := tok.GetChatNotes(ctx, a); !errors.Is(err, ErrChatNotFound) {
		t.Fatalf("outside token set: %v", err)
	}
	if n, err := tok.GetChatNotes(ctx, b); err != nil || n.Version != 1 {
		t.Fatalf("inside token set: %+v %v", n, err)
	}
	vs, _ := tok.NotesVersions(ctx)
	if len(vs) != 1 || vs[b] != 1 {
		t.Fatalf("versions under token: %v", vs)
	}
	if _, _, err := tok.MessagesAfterNotes(ctx, ChatNotes{ChatJID: a}, 10); !errors.Is(err, ErrChatNotFound) {
		t.Fatalf("messages outside token set: %v", err)
	}
}

// Denying or resetting a chat deletes its notes; allowing keeps them.
func TestChatNotes_DeletedWithAccess(t *testing.T) {
	st, a, b, _ := notesFixture(t)
	ctx := context.Background()
	for _, jid := range []string{a, b} {
		if _, err := st.UpdateChatNotes(ctx, jid, "notes", "", 0); err != nil {
			t.Fatal(err)
		}
		if _, err := st.UpdateChatNotes(ctx, jid, "notes v2", "", 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SetChatAccess(ctx, a, AccessAllowed, ""); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.GetChatNotes(ctx, a); n.Version != 2 {
		t.Fatalf("allow dropped notes: %+v", n)
	}
	if err := st.SetChatAccess(ctx, a, AccessDenied, ""); err != nil {
		t.Fatal(err)
	}
	if err := st.SetChatAccess(ctx, b, AccessDefault, ""); err != nil {
		t.Fatal(err)
	}
	for _, jid := range []string{a, b} {
		n, _ := st.GetChatNotes(ctx, jid)
		h, _ := st.ChatNotesHistory(ctx, jid)
		if n.Version != 0 || len(h) != 0 {
			t.Fatalf("%s kept notes: %+v %d", jid, n, len(h))
		}
	}
}
