package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/murandido/mcp-wpp/internal/auth"
	"github.com/murandido/mcp-wpp/internal/store"
)

// An OAuth access token is an ordinary client token: its approved scopes and
// chats apply to every tool exactly as for `wpp-mcp token create`.
func TestOAuthToken_ScopesAndChatsApply(t *testing.T) {
	s, st := tokenServer(t, Options{ConfirmSends: true})
	ctx := context.Background()
	toks, err := st.CreateOAuthGrant(ctx, store.NewOAuthGrant{
		ClientID: "wppc_test", ClientName: "Claude", Scopes: []string{auth.ScopeRead},
		Chats: []string{carolJID}, Audience: "https://wpp.test/mcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := st.VerifyAPIToken(ctx, toks.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	callerCtx := auth.WithIdentity(ctx, tok.Identity())

	res := callToolAs(t, s, callerCtx, "list_chats", map[string]any{})
	if res.IsError || !strings.Contains(res.Text, "Carol") || strings.Contains(res.Text, "Alice") || strings.Contains(res.Text, "Bob Secret") {
		t.Fatalf("list_chats with an OAuth token limited to Carol: %+v", res)
	}
	res = callToolAs(t, s, callerCtx, "send_message", map[string]any{"recipient": "447700000003", "message": "hi"})
	if !res.IsError || !strings.Contains(res.Text, "needs the send scope") {
		t.Fatalf("send_message with a read-only OAuth token: %+v", res)
	}
	if ps, _ := st.ListProposals(ctx, ""); len(ps) != 0 {
		t.Fatalf("a read-only OAuth token recorded proposals: %+v", ps)
	}
	entries, _ := st.ListAudit(ctx, store.AuditFilter{})
	if len(entries) == 0 || !strings.HasPrefix(entries[0].Actor, "token:oauth:Claude#") {
		t.Fatalf("audit actor: %+v", entries)
	}
}
