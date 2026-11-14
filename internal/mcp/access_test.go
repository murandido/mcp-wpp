package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/client"
	"github.com/murandido/mcp-wpp/internal/store"
)

func TestEveryToolHasAccessScope(t *testing.T) {
	tools := NewServer(nil, nil, true).MCP().ListTools()
	for name := range tools {
		if _, ok := toolAccessScope[name]; !ok {
			t.Errorf("tool %q has no access classification in access.go", name)
		}
	}
	for name := range toolAccessScope {
		if tools[name] == nil {
			t.Errorf("access.go classifies unregistered tool %q", name)
		}
	}
}

const (
	visibleJID = "447700000001@s.whatsapp.net"
	hiddenJID  = "447700000002@s.whatsapp.net"
)

func accessServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	for jid, name := range map[string]string{visibleJID: "Alice", hiddenJID: "Bob Secret"} {
		if err := st.StoreChat(jid, name, now); err != nil {
			t.Fatal(err)
		}
		id := "msg-visible"
		if jid == hiddenJID {
			id = "msg-hidden"
		}
		if err := st.StoreMessage(ctx, store.Message{ID: id, ChatJID: jid, Sender: jid, Content: "hello from " + name, Timestamp: now}, nil, nil, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SetChatAccess(ctx, visibleJID, store.AccessAllowed, ""); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(ctx, client.Config{StoreDir: dir, Store: st, Logger: client.NewStderrLogger("test", "ERROR", false)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Disconnect)
	srv, err := NewServerWithOptions(c, nil, Options{Tools: &ToolSelection{Enable: []string{"all"}}})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st
}

type toolResponse struct {
	IsError bool
	Text    string
}

func callToolDirect(t *testing.T, s *Server, name string, args map[string]any) toolResponse {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args},
	})
	out, _ := json.Marshal(s.MCP().HandleMessage(context.Background(), raw))
	var env struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("decode %s: %v", out, err)
	}
	var texts []string
	for _, c := range env.Result.Content {
		texts = append(texts, c.Text)
	}
	return toolResponse{IsError: env.Result.IsError, Text: strings.Join(texts, "\n")}
}

func TestAccess_ListToolsOnlySeeAllowedChats(t *testing.T) {
	s, _ := accessServer(t)
	for _, call := range []struct {
		tool string
		args map[string]any
	}{
		{"list_chats", map[string]any{}},
		{"list_messages", map[string]any{"query": "hello"}},
		{"list_messages", map[string]any{"chat_jid": hiddenJID}},
		{"search_contacts", map[string]any{"query": "bob"}},
		{"get_message_context", map[string]any{"message_id": "msg-hidden"}},
		{"digest", map[string]any{}},
		{"digest", map[string]any{"chat_jids": []string{hiddenJID}}},
	} {
		res := callToolDirect(t, s, call.tool, call.args)
		if strings.Contains(res.Text, "Bob Secret") || strings.Contains(res.Text, hiddenJID) {
			t.Errorf("%s %v leaked the hidden chat: %s", call.tool, call.args, res.Text)
		}
	}
	if res := callToolDirect(t, s, "list_chats", map[string]any{}); !strings.Contains(res.Text, "Alice") {
		t.Errorf("list_chats hides the allowed chat: %s", res.Text)
	}
	if res := callToolDirect(t, s, "digest", map[string]any{"hours": 1}); !strings.Contains(res.Text, "hello from Alice") {
		t.Errorf("digest misses the allowed chat: %s", res.Text)
	}
}

func TestAccess_ChatToolsRefuseHiddenChats(t *testing.T) {
	s, _ := accessServer(t)
	nonexistent := "449999999999@s.whatsapp.net"
	for _, tool := range []string{"get_chat", "download_media", "request_sync", "get_poll_results"} {
		args := map[string]any{"chat_jid": hiddenJID, "message_id": "x", "poll_message_id": "x"}
		hidden := callToolDirect(t, s, tool, args)
		args["chat_jid"] = nonexistent
		missing := callToolDirect(t, s, tool, args)
		if !hidden.IsError || !strings.Contains(hidden.Text, "chat not found") {
			t.Errorf("%s on a hidden chat: %+v", tool, hidden)
		}
		if strings.Replace(hidden.Text, hiddenJID, "X", 1) != strings.Replace(missing.Text, nonexistent, "X", 1) {
			t.Errorf("%s distinguishes hidden from missing chats: %q vs %q", tool, hidden.Text, missing.Text)
		}
	}
	// Bare phone digits resolve to the same chat and are refused too.
	if res := callToolDirect(t, s, "send_message", map[string]any{"recipient": "447700000002", "message": "hi"}); !strings.Contains(res.Text, "chat not found") {
		t.Errorf("send_message to a hidden chat by digits: %+v", res)
	}
	if res := callToolDirect(t, s, "get_chat", map[string]any{"chat_jid": visibleJID}); res.IsError {
		t.Errorf("get_chat on the allowed chat failed: %s", res.Text)
	}
}

func TestAccess_RequestToolRevealsNothing(t *testing.T) {
	s, st := accessServer(t)
	res := callToolDirect(t, s, "request_chat_access", map[string]any{"query": "bob", "reason": "user asked"})
	if res.IsError {
		t.Fatal(res.Text)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Text), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out["status"] != "pending" || out["request_id"] == nil {
		t.Fatalf("request_chat_access must return only id and status: %v", out)
	}
	if ok, _ := st.ChatAllowed(context.Background(), hiddenJID); ok {
		t.Fatal("request granted access by itself")
	}
}

func TestAccess_MediaResourceRefusesHiddenChat(t *testing.T) {
	s, _ := accessServer(t)
	raw := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"whatsapp://media/%s/m1"}}`, strings.ReplaceAll(hiddenJID, "@", "%40"))
	out, _ := json.Marshal(s.MCP().HandleMessage(context.Background(), json.RawMessage(raw)))
	if !strings.Contains(string(out), "chat not found") {
		t.Fatalf("resource read of a hidden chat: %s", out)
	}
}
