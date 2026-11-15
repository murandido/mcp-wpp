package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/client"
	"github.com/murandido/mcp-wpp/internal/store"
)

// policyServer is a write-mode server over a real store with Alice visible
// and Bob hidden. confirm is the -confirm-sends flag.
func policyServer(t *testing.T, confirm bool) (*Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	_ = st.StoreChat(visibleJID, "Alice", time.Now())
	_ = st.StoreChat(hiddenJID, "Bob Secret", time.Now())
	_ = st.SetChatAccess(context.Background(), visibleJID, store.AccessAllowed, "")
	c, err := client.New(context.Background(), client.Config{StoreDir: dir, Store: st, Logger: client.NewStderrLogger("test", "ERROR", false)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Disconnect)
	srv, err := NewServerWithOptions(c, nil, Options{ConfirmSends: confirm, Tools: &ToolSelection{Enable: []string{"all"}}})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st
}

func isProposal(res toolResponse) bool {
	var out struct {
		Status string `json:"status"`
	}
	return json.Unmarshal([]byte(res.Text), &out) == nil && out.Status == "awaiting_approval"
}

func TestSendPolicy_DefaultFollowsFlags(t *testing.T) {
	confirming, _ := policyServer(t, true)
	if confirming.DefaultSendPolicy() != store.SendConfirm {
		t.Fatalf("default with -confirm-sends: %s", confirming.DefaultSendPolicy())
	}
	if res := callToolDirect(t, confirming, "send_message", map[string]any{"recipient": visibleJID, "message": "x"}); !isProposal(res) {
		t.Fatalf("-confirm-sends must propose: %+v", res)
	}
	direct, _ := policyServer(t, false)
	if direct.DefaultSendPolicy() != store.SendDirect {
		t.Fatalf("default with -confirm-sends=false: %s", direct.DefaultSendPolicy())
	}
	res := callToolDirect(t, direct, "send_message", map[string]any{"recipient": visibleJID, "message": "x"})
	if isProposal(res) || !strings.Contains(res.Text, "Not connected") {
		t.Fatalf("-confirm-sends=false must act (and fail, unpaired): %+v", res)
	}
	if ro := NewReadOnlyServer(nil, nil, false); ro.DefaultSendPolicy() != store.SendNone {
		t.Fatal("read-only servers allow no writes")
	}
}

func TestSendPolicy_PerChatOverridesDefault(t *testing.T) {
	ctx := context.Background()
	for _, confirm := range []bool{true, false} {
		s, st := policyServer(t, confirm)
		send := func() toolResponse {
			return callToolDirect(t, s, "send_message", map[string]any{"recipient": visibleJID, "message": "x"})
		}

		_ = st.SetChatSendPolicy(ctx, visibleJID, store.SendNone)
		if res := send(); !res.IsError || !strings.Contains(res.Text, `send policy "none"`) {
			t.Fatalf("confirm=%v, none: %+v", confirm, res)
		}
		// none also covers trivial writes that skip the outbox.
		if res := callToolDirect(t, s, "mark_chat_read", map[string]any{"chat_jid": visibleJID}); !strings.Contains(res.Text, `send policy "none"`) {
			t.Fatalf("confirm=%v, none, mark_chat_read: %+v", confirm, res)
		}

		_ = st.SetChatSendPolicy(ctx, visibleJID, store.SendConfirm)
		if res := send(); !isProposal(res) {
			t.Fatalf("confirm=%v, confirm: %+v", confirm, res)
		}

		_ = st.SetChatSendPolicy(ctx, visibleJID, store.SendDirect)
		if res := send(); isProposal(res) || !strings.Contains(res.Text, "Not connected") {
			t.Fatalf("confirm=%v, direct: %+v", confirm, res)
		}
	}
}

func TestSendPolicy_HiddenChatStaysNotFound(t *testing.T) {
	s, st := policyServer(t, true)
	ctx := context.Background()
	for _, p := range []string{store.SendNone, store.SendConfirm, store.SendDirect} {
		_ = st.SetChatSendPolicy(ctx, hiddenJID, p)
		for _, tool := range []string{"send_message", "schedule_message"} {
			res := callToolDirect(t, s, tool, map[string]any{"recipient": hiddenJID, "message": "x", "send_at": time.Now().Add(time.Hour).Format(time.RFC3339)})
			if !strings.Contains(res.Text, "chat not found") || strings.Contains(res.Text, "policy") {
				t.Fatalf("%s to a hidden chat with policy %s: %+v", tool, p, res)
			}
		}
	}
	// Exactly the error a nonexistent chat gets.
	missing := callToolDirect(t, s, "send_message", map[string]any{"recipient": "447700000099@s.whatsapp.net", "message": "x"})
	hidden := callToolDirect(t, s, "send_message", map[string]any{"recipient": hiddenJID, "message": "x"})
	if strings.ReplaceAll(missing.Text, "447700000099", "N") != strings.ReplaceAll(hidden.Text, "447700000002", "N") {
		t.Fatalf("hidden and missing chats differ:\n%s\n%s", missing.Text, hidden.Text)
	}
}

func TestSendPolicy_GlobalToolsKeepDefault(t *testing.T) {
	s, _ := policyServer(t, true)
	if res := callToolDirect(t, s, "set_status_message", map[string]any{"text": "hi"}); !isProposal(res) {
		t.Fatalf("a tool without a chat uses the default (confirm): %+v", res)
	}
	d, _ := policyServer(t, false)
	if res := callToolDirect(t, d, "set_status_message", map[string]any{"text": "hi"}); isProposal(res) {
		t.Fatalf("a tool without a chat uses the default (direct): %+v", res)
	}
}

func TestSendPolicy_ApprovalRechecksPolicy(t *testing.T) {
	s, st := policyServer(t, true)
	ctx := context.Background()
	id := proposalID(t, callToolDirect(t, s, "send_message", map[string]any{"recipient": visibleJID, "message": "x"}))
	_ = st.SetChatSendPolicy(ctx, visibleJID, store.SendNone)
	p, err := s.ApproveProposal(ctx, id)
	if err != nil || p.Status != store.OutboxFailed || !strings.Contains(p.Result, `send policy "none"`) {
		t.Fatalf("approval after turning sends off: %+v %v", p, err)
	}
}
