package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/client"
	"github.com/murandido/mcp-wpp/internal/store"
)

func confirmServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	_ = st.StoreChat(visibleJID, "Alice", time.Now())
	_ = st.SetChatAccess(context.Background(), visibleJID, store.AccessAllowed, "")
	c, err := client.New(context.Background(), client.Config{StoreDir: dir, Store: st, Logger: client.NewStderrLogger("test", "ERROR", false)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Disconnect)
	srv, err := NewServerWithOptions(c, nil, Options{ConfirmSends: true, Tools: &ToolSelection{}})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st
}

func proposalID(t *testing.T, res toolResponse) int64 {
	t.Helper()
	var out struct {
		ID     int64  `json:"proposal_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(res.Text), &out); err != nil || out.Status != "awaiting_approval" {
		t.Fatalf("expected a proposal, got %+v", res)
	}
	return out.ID
}

func TestConfirm_SendBecomesProposalAndRunsOnce(t *testing.T) {
	s, _ := confirmServer(t)
	ctx := context.Background()
	res := callToolDirect(t, s, "send_message", map[string]any{"recipient": "447700000001", "message": "see you at 8"})
	id := proposalID(t, res)
	if !strings.Contains(res.Text, "Alice") || !strings.Contains(res.Text, "see you at 8") {
		t.Fatalf("summary should name the chat and quote the text: %s", res.Text)
	}

	p, err := s.ApproveProposal(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	// The daemon is not connected to WhatsApp, so the send itself fails;
	// that proves approval ran the real tool rather than another proposal.
	if p.Status != "failed" || strings.Contains(p.Result, "proposal") {
		t.Fatalf("approved proposal: %+v", p)
	}
	if _, err := s.ApproveProposal(ctx, id); !errors.Is(err, store.ErrProposalNotPending) {
		t.Fatalf("second approval: %v", err)
	}
}

func TestReportsFailure(t *testing.T) {
	if !reportsFailure(`{"Success": false, "Message": "x"}`) || reportsFailure(`{"Success": true}`) || reportsFailure("Reaction sent") {
		t.Fatal("reportsFailure misclassifies results")
	}
}

func TestConfirm_HiddenChatRefusedBeforeAndAfter(t *testing.T) {
	s, st := confirmServer(t)
	ctx := context.Background()
	if res := callToolDirect(t, s, "send_message", map[string]any{"recipient": hiddenJID, "message": "x"}); !strings.Contains(res.Text, "chat not found") {
		t.Fatalf("proposal for a hidden chat: %+v", res)
	}
	id := proposalID(t, callToolDirect(t, s, "send_message", map[string]any{"recipient": visibleJID, "message": "x"}))
	// The user hides the chat before approving: the send must not happen.
	_ = st.SetChatAccess(ctx, visibleJID, store.AccessDenied, "")
	p, err := s.ApproveProposal(ctx, id)
	if err != nil || p.Status != "failed" || !strings.Contains(p.Result, "chat not found") {
		t.Fatalf("approval after hiding the chat: %+v %v", p, err)
	}
}

func TestConfirm_RejectAndExpiry(t *testing.T) {
	s, st := confirmServer(t)
	ctx := context.Background()
	id := proposalID(t, callToolDirect(t, s, "send_message", map[string]any{"recipient": visibleJID, "message": "a"}))
	if err := s.RejectProposal(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveProposal(ctx, id); !errors.Is(err, store.ErrProposalNotPending) {
		t.Fatalf("approving a rejected proposal: %v", err)
	}
	id = proposalID(t, callToolDirect(t, s, "send_message", map[string]any{"recipient": visibleJID, "message": "b"}))
	if _, err := st.DB().Exec("UPDATE outbox SET expires_at = ? WHERE id = ?", time.Now().Add(-time.Minute), id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveProposal(ctx, id); !errors.Is(err, store.ErrProposalNotPending) {
		t.Fatalf("approving an expired proposal: %v", err)
	}
}

func TestConfirm_ReadToolsAndTrivialWritesSkipTheOutbox(t *testing.T) {
	s, _ := confirmServer(t)
	if res := callToolDirect(t, s, "list_chats", map[string]any{}); strings.Contains(res.Text, "proposal_id") {
		t.Fatal("read tools must not create proposals")
	}
	for tool := range noConfirm {
		if readOnlyToolAccess[tool] {
			continue
		}
		if needsConfirmation(tool) {
			t.Errorf("%s should skip confirmation", tool)
		}
	}
	if !needsConfirmation("send_file") || !needsConfirmation("delete_message") || !needsConfirmation("set_privacy_setting") {
		t.Fatal("sends and account changes must need confirmation")
	}
}
