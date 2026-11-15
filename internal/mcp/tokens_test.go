package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/auth"
	"github.com/murandido/mcp-wpp/internal/client"
	"github.com/murandido/mcp-wpp/internal/store"
)

const carolJID = "447700000003@s.whatsapp.net"

// tokenServer is accessServer with a second allowed chat (Carol), built
// with opts and auditing into the same store.
func tokenServer(t *testing.T, opts Options) (*Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	for _, c := range []struct{ jid, name, msg string }{
		{visibleJID, "Alice", "msg-alice"},
		{hiddenJID, "Bob Secret", "msg-hidden"},
		{carolJID, "Carol", "msg-carol"},
	} {
		if err := st.StoreChat(c.jid, c.name, now); err != nil {
			t.Fatal(err)
		}
		if err := st.StoreMessage(ctx, store.Message{ID: c.msg, ChatJID: c.jid, Sender: c.jid, Content: "hello from " + c.name, Timestamp: now}, nil, nil, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	for _, jid := range []string{visibleJID, carolJID} {
		if err := st.SetChatAccess(ctx, jid, store.AccessAllowed, ""); err != nil {
			t.Fatal(err)
		}
	}
	c, err := client.New(ctx, client.Config{StoreDir: dir, Store: st, Logger: client.NewStderrLogger("test", "ERROR", false)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Disconnect)
	opts.Tools = &ToolSelection{Enable: []string{"all"}}
	opts.Audit = st
	srv, err := NewServerWithOptions(c, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	return srv, st
}

func callToolAs(t *testing.T, s *Server, ctx context.Context, name string, args map[string]any) toolResponse {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args},
	})
	return decodeToolResponse(t, s.MCP().HandleMessage(ctx, raw))
}

func decodeToolResponse(t *testing.T, msg any) toolResponse {
	t.Helper()
	out, _ := json.Marshal(msg)
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

func tokenCtx(scopes []string, chats []string) context.Context {
	return auth.WithIdentity(context.Background(), auth.Identity{Kind: auth.KindToken, TokenID: 7, Name: "connector", Scopes: scopes, Chats: chats})
}

func TestTokens_ReadScopeCannotSend(t *testing.T) {
	s, st := tokenServer(t, Options{ConfirmSends: true})
	ctx := tokenCtx([]string{auth.ScopeRead}, nil)
	for _, call := range []struct {
		tool string
		args map[string]any
	}{
		{"send_message", map[string]any{"recipient": "447700000001", "message": "hi"}},
		{"mark_chat_read", map[string]any{"chat_jid": visibleJID}},
		{"set_status_message", map[string]any{"status": "x"}},
	} {
		res := callToolAs(t, s, ctx, call.tool, call.args)
		if !res.IsError || !strings.Contains(res.Text, "needs the send scope") {
			t.Errorf("%s with a read token: %+v", call.tool, res)
		}
	}
	if ps, _ := st.ListProposals(context.Background(), ""); len(ps) != 0 {
		t.Fatalf("a read token recorded proposals: %+v", ps)
	}
	if res := callToolAs(t, s, ctx, "list_chats", map[string]any{}); res.IsError || !strings.Contains(res.Text, "Alice") {
		t.Fatalf("read token cannot read: %+v", res)
	}
	// With send, a write is proposed as usual.
	res := callToolAs(t, s, tokenCtx([]string{auth.ScopeRead, auth.ScopeSend}, nil), "send_message", map[string]any{"recipient": "447700000001", "message": "hi"})
	if res.IsError || !strings.Contains(res.Text, "proposal_id") {
		t.Fatalf("send token: %+v", res)
	}
}

func TestTokens_ChatRestrictionNarrowsEveryRead(t *testing.T) {
	s, _ := tokenServer(t, Options{})
	ctx := tokenCtx([]string{auth.ScopeRead}, []string{carolJID, hiddenJID})
	for _, call := range []struct {
		tool string
		args map[string]any
	}{
		{"list_chats", map[string]any{}},
		{"list_messages", map[string]any{"query": "hello"}},
		{"list_messages", map[string]any{"chat_jid": visibleJID}},
		{"search_contacts", map[string]any{"query": "alice"}},
		{"get_message_context", map[string]any{"message_id": "msg-alice"}},
		{"digest", map[string]any{}},
		{"digest", map[string]any{"chat_jids": []string{visibleJID}}},
	} {
		res := callToolAs(t, s, ctx, call.tool, call.args)
		for _, leak := range []string{"Alice", visibleJID, "Bob Secret", hiddenJID} {
			if strings.Contains(res.Text, leak) {
				t.Errorf("%s %v leaked %q outside the token's chats: %s", call.tool, call.args, leak, res.Text)
			}
		}
	}
	if res := callToolAs(t, s, ctx, "list_chats", map[string]any{}); !strings.Contains(res.Text, "Carol") {
		t.Errorf("list_chats hides the token's allowed chat: %s", res.Text)
	}
	if res := callToolAs(t, s, ctx, "digest", map[string]any{"hours": 1}); !strings.Contains(res.Text, "hello from Carol") {
		t.Errorf("digest misses the token's chat: %s", res.Text)
	}

	// A chat-argument tool treats a chat outside the token set exactly like
	// one that does not exist.
	nonexistent := "449999999999@s.whatsapp.net"
	for _, tool := range []string{"get_chat", "download_media", "get_poll_results"} {
		args := map[string]any{"chat_jid": visibleJID, "message_id": "x", "poll_message_id": "x"}
		hidden := callToolAs(t, s, ctx, tool, args)
		args["chat_jid"] = nonexistent
		missing := callToolAs(t, s, ctx, tool, args)
		if !hidden.IsError || strings.Replace(hidden.Text, visibleJID, "X", 1) != strings.Replace(missing.Text, nonexistent, "X", 1) {
			t.Errorf("%s distinguishes a token-hidden chat: %q vs %q", tool, hidden.Text, missing.Text)
		}
	}
	if res := callToolAs(t, s, ctx, "get_chat", map[string]any{"chat_jid": carolJID}); res.IsError {
		t.Errorf("get_chat on the token's chat: %s", res.Text)
	}
	// The token cannot widen the policy: Bob is in its set but not allowed.
	if res := callToolAs(t, s, ctx, "get_chat", map[string]any{"chat_jid": hiddenJID}); !res.IsError {
		t.Errorf("token widened the policy: %s", res.Text)
	}

	raw := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"whatsapp://media/%s/m1"}}`, strings.ReplaceAll(visibleJID, "@", "%40"))
	out, _ := json.Marshal(s.MCP().HandleMessage(ctx, json.RawMessage(raw)))
	if !strings.Contains(string(out), "chat not found") {
		t.Fatalf("media resource outside the token's chats: %s", out)
	}
}

func TestAudit_RecordsToolCallsWithoutContent(t *testing.T) {
	s, st := tokenServer(t, Options{ConfirmSends: true})
	read := tokenCtx([]string{auth.ScopeRead}, []string{carolJID})
	callToolAs(t, s, read, "list_messages", map[string]any{"query": "secret search words"})       // ok
	callToolAs(t, s, read, "get_chat", map[string]any{"chat_jid": visibleJID})                    // denied by token
	callToolAs(t, s, read, "send_message", map[string]any{"recipient": carolJID, "message": "x"}) // denied by scope
	callToolAs(t, s, read, "list_messages", map[string]any{"after": "not a date"})                // error
	callToolAs(t, s, context.Background(), "send_message", map[string]any{"recipient": "447700000001", "message": "private words"})
	raw := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"whatsapp://media/%s/m1"}}`, strings.ReplaceAll(hiddenJID, "@", "%40"))
	s.MCP().HandleMessage(read, json.RawMessage(raw))

	entries, err := st.ListAudit(context.Background(), store.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 6 {
		t.Fatalf("want 6 entries, got %+v", entries)
	}
	// Newest first.
	want := []struct{ actor, action, chat, outcome string }{
		{"token:connector", mediaResourceAction, hiddenJID, store.OutcomeDenied},
		{"operator", "send_message", visibleJID, store.OutcomeProposed},
		{"token:connector", "list_messages", "", store.OutcomeError},
		{"token:connector", "send_message", carolJID, store.OutcomeDenied},
		{"token:connector", "get_chat", visibleJID, store.OutcomeDenied},
		{"token:connector", "list_messages", "", store.OutcomeOK},
	}
	for i, w := range want {
		e := entries[i]
		if e.Actor != w.actor || e.Action != w.action || e.ChatJID != w.chat || e.Outcome != w.outcome {
			t.Errorf("entry %d: got %+v, want %+v", i, e, w)
		}
		if w.actor != "operator" && e.TokenID != 7 {
			t.Errorf("entry %d: token id %d", i, e.TokenID)
		}
	}
	dump, _ := json.Marshal(entries)
	for _, leak := range []string{"secret search words", "private words", "hello from"} {
		if bytes.Contains(dump, []byte(leak)) {
			t.Fatalf("audit log holds content %q: %s", leak, dump)
		}
	}
}

func TestAudit_DisabledRecordsNothing(t *testing.T) {
	s, st := tokenServer(t, Options{})
	s.auditor = nil
	callToolAs(t, s, context.Background(), "list_chats", map[string]any{})
	if es, _ := st.ListAudit(context.Background(), store.AuditFilter{}); len(es) != 0 {
		t.Fatalf("audit disabled but recorded %+v", es)
	}
}

// TestTokens_IdentityFlowsThroughStreamableHTTP checks that mcp-go hands the
// HTTP request context, where the daemon's guard puts the identity, to tool
// handlers.
func TestTokens_IdentityFlowsThroughStreamableHTTP(t *testing.T) {
	s, _ := tokenServer(t, Options{})
	mux := http.NewServeMux()
	s.AttachHTTP(mux)
	id := auth.Identity{Kind: auth.KindToken, TokenID: 9, Name: "remote", Scopes: []string{auth.ScopeRead}, Chats: []string{carolJID}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(auth.WithIdentity(r.Context(), id)))
	}))
	defer srv.Close()

	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "list_chats", "arguments": map[string]any{}},
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	text := string(raw)
	if resp.StatusCode != http.StatusOK || !strings.Contains(text, "Carol") || strings.Contains(text, "Alice") {
		t.Fatalf("list_chats over HTTP as a restricted token: %d %s", resp.StatusCode, text)
	}
}
