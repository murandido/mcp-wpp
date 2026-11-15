package store

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/auth"
)

func openFileStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestAPITokens_CreateVerifyRevoke(t *testing.T) {
	st := openFileStore(t)
	ctx := context.Background()
	tok, plain, err := st.CreateAPIToken(ctx, NewAPIToken{Name: "claude-ai", Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	if !auth.LooksLikeToken(plain) || tok.ID == 0 || tok.Chats != nil {
		t.Fatalf("created %+v %q", tok, plain)
	}
	// Only the hash is stored.
	var stored []byte
	if err := st.DB().QueryRow("SELECT token_hash FROM api_tokens WHERE id = ?", tok.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, auth.HashToken(plain)) || bytes.Contains(stored, []byte(plain)) {
		t.Fatal("stored value is not the token's SHA-256")
	}

	got, err := st.VerifyAPIToken(ctx, plain)
	if err != nil || got.ID != tok.ID || got.Identity().Has(auth.ScopeSend) || got.LastUsedAt == nil {
		t.Fatalf("verify: %+v %v", got, err)
	}
	if _, _, err := st.CreateAPIToken(ctx, NewAPIToken{Name: "claude-ai", Scopes: []string{"read"}}); err == nil {
		t.Fatal("duplicate name accepted")
	}
	for _, bad := range []NewAPIToken{
		{Name: "", Scopes: []string{"read"}},
		{Name: "12", Scopes: []string{"read"}},
		{Name: "a b", Scopes: []string{"read"}},
		{Name: "x", Scopes: []string{"send"}},
		{Name: "y", Scopes: []string{"read"}, Chats: []string{"Alice"}},
		{Name: "z", Scopes: []string{"read"}, ExpiresAt: new(time.Now().Add(-time.Hour))},
	} {
		if _, _, err := st.CreateAPIToken(ctx, bad); err == nil {
			t.Errorf("invalid token accepted: %+v", bad)
		}
	}

	other, _ := auth.NewToken()
	for _, p := range []string{other, "", plain + "0", "wppmcp_" + string(bytes.Repeat([]byte("g"), 64))} {
		if _, err := st.VerifyAPIToken(ctx, p); !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("verify(%q): %v", p, err)
		}
	}

	if _, err := st.RevokeAPIToken(ctx, "claude-ai"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.VerifyAPIToken(ctx, plain); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("revoked token verified: %v", err)
	}
	list, _ := st.ListAPITokens(ctx)
	if len(list) != 1 || list[0].Status(time.Now()) != "revoked" {
		t.Fatalf("list after revoke: %+v", list)
	}
	if _, err := st.RevokeAPIToken(ctx, "missing"); err == nil {
		t.Fatal("revoking a missing token succeeded")
	}
}

func TestAPITokens_ExpiryAndTouch(t *testing.T) {
	st := openFileStore(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)
	tok, plain, err := st.CreateAPIToken(ctx, NewAPIToken{Name: "short", Scopes: []string{"read", "send"}, ExpiresAt: &exp})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.VerifyAPIToken(ctx, plain); err != nil {
		t.Fatal(err)
	}
	// A recent use is not rewritten; an old one is.
	old := time.Now().UTC().Add(-30 * time.Second)
	if _, err := st.DB().Exec("UPDATE api_tokens SET last_used_at = ? WHERE id = ?", old, tok.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := st.VerifyAPIToken(ctx, plain)
	if !got.LastUsedAt.Equal(old) {
		t.Fatalf("last_used_at rewritten within a minute: %v", got.LastUsedAt)
	}
	older := time.Now().UTC().Add(-2 * time.Minute)
	if _, err := st.DB().Exec("UPDATE api_tokens SET last_used_at = ? WHERE id = ?", older, tok.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.VerifyAPIToken(ctx, plain); !got.LastUsedAt.After(older.Add(time.Minute)) {
		t.Fatalf("stale last_used_at not refreshed: %v", got.LastUsedAt)
	}

	if _, err := st.DB().Exec("UPDATE api_tokens SET expires_at = ? WHERE id = ?", time.Now().UTC().Add(-time.Second), tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.VerifyAPIToken(ctx, plain); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expired token verified: %v", err)
	}
	if list, _ := st.ListAPITokens(ctx); list[0].Status(time.Now()) != "expired" {
		t.Fatalf("status: %s", list[0].Status(time.Now()))
	}
}

func TestScopedTo_NarrowsThePolicyInSQL(t *testing.T) {
	st := openFileStore(t)
	ctx := context.Background()
	a, b, c := "447700000001@s.whatsapp.net", "447700000002@s.whatsapp.net", "447700000003@s.whatsapp.net"
	now := time.Now().UTC()
	for _, jid := range []string{a, b, c} {
		if err := st.StoreChat(jid, "chat "+jid[:12], now); err != nil {
			t.Fatal(err)
		}
		if err := st.StoreMessage(ctx, Message{ID: "m-" + jid[:12], ChatJID: jid, Sender: jid, Content: "hello", Timestamp: now}, nil, nil, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	// The policy allows a and b; the token names b and c.
	for _, jid := range []string{a, b} {
		if err := st.SetChatAccess(ctx, jid, AccessAllowed, ""); err != nil {
			t.Fatal(err)
		}
	}
	view := st.ScopedTo([]string{b, c})
	chats, err := view.ListChats(ctx, "", 100, 0, false, "")
	if err != nil || len(chats) != 1 || chats[0].JID != b {
		t.Fatalf("ListChats: %+v %v", chats, err)
	}
	msgs, err := view.ListMessages(ctx, ListMessagesParams{Query: "hello", Limit: 100})
	if err != nil || len(msgs) != 1 || msgs[0].ChatJID != b {
		t.Fatalf("ListMessages: %+v %v", msgs, err)
	}
	for jid, want := range map[string]bool{a: false, b: true, c: false} {
		if ok, _ := view.ChatAllowed(ctx, jid); ok != want {
			t.Errorf("ChatAllowed(%s) = %v", jid, ok)
		}
	}
	if ch, _ := view.GetChat(ctx, a, false); ch != nil {
		t.Fatal("GetChat returned a chat outside the token set")
	}
	if d, _ := view.Digest(ctx, now.Add(-time.Hour), nil, 5, 10); len(d) != 1 || d[0].Chat.JID != b {
		t.Fatalf("Digest: %+v", d)
	}
	// No restriction is the plain policy; an empty set shows nothing.
	if chats, _ := st.ScopedTo(nil).ListChats(ctx, "", 100, 0, false, ""); len(chats) != 2 {
		t.Fatalf("unrestricted view: %d chats", len(chats))
	}
	if chats, _ := st.ScopedTo([]string{}).ListChats(ctx, "", 100, 0, false, ""); len(chats) != 0 {
		t.Fatalf("empty token set: %d chats", len(chats))
	}
}

func TestAudit_RecordListPrune(t *testing.T) {
	st := openFileStore(t)
	ctx := context.Background()
	old := time.Now().Add(-100 * 24 * time.Hour)
	for _, e := range []AuditEntry{
		{At: old, Actor: "operator", Kind: AuditAdmin, Action: "POST /admin/access/chat", ChatJID: "1@s.whatsapp.net", Outcome: OutcomeOK},
		{Actor: "token:claude-ai", TokenID: 4, Kind: AuditTool, Action: "list_chats", Outcome: OutcomeOK, Duration: 3},
		{Actor: "token:claude-ai", TokenID: 4, Kind: AuditTool, Action: "get_chat", ChatJID: "2@s.whatsapp.net", Outcome: OutcomeDenied},
	} {
		if err := st.RecordAudit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.RecordAudit(ctx, AuditEntry{Actor: "x", Kind: AuditTool, Action: "a", Outcome: "maybe"}); err == nil {
		t.Fatal("unknown outcome accepted")
	}
	all, _ := st.ListAudit(ctx, AuditFilter{})
	if len(all) != 3 || all[0].Action != "get_chat" || all[0].TokenID != 4 {
		t.Fatalf("list: %+v", all)
	}
	if es, _ := st.ListAudit(ctx, AuditFilter{Actor: "claude-ai"}); len(es) != 2 {
		t.Fatalf("by token name: %d", len(es))
	}
	if es, _ := st.ListAudit(ctx, AuditFilter{Actor: "operator"}); len(es) != 1 {
		t.Fatalf("by operator: %d", len(es))
	}
	if es, _ := st.ListAudit(ctx, AuditFilter{ChatJID: "2@s.whatsapp.net"}); len(es) != 1 || es[0].Outcome != OutcomeDenied {
		t.Fatalf("by chat: %+v", es)
	}
	if es, _ := st.ListAudit(ctx, AuditFilter{Since: time.Now().Add(-time.Hour)}); len(es) != 2 {
		t.Fatalf("since: %d", len(es))
	}
	n, err := st.PruneAudit(ctx, time.Now().Add(-90*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	if es, _ := st.ListAudit(ctx, AuditFilter{}); len(es) != 2 {
		t.Fatalf("after prune: %d", len(es))
	}
}

// The digest query itself must honour a token's chat set, not only the
// per-chat lookups after it (hidden chats must not even take group slots).
func TestDigestWith_HonoursTokenChats(t *testing.T) {
	st := openFileStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for jid, name := range map[string]string{"447700000001@s.whatsapp.net": "Alice", "447700000002@s.whatsapp.net": "Bob"} {
		if err := st.StoreChat(jid, name, now); err != nil {
			t.Fatal(err)
		}
		if err := st.StoreMessage(ctx, Message{ID: "m-" + name, ChatJID: jid, Sender: jid, Content: "hello from " + name, Timestamp: now}, nil, nil, nil, 0); err != nil {
			t.Fatal(err)
		}
		_ = st.SetChatAccess(ctx, jid, AccessAllowed, "")
	}
	scoped := st.Scoped().ScopedTo([]string{"447700000001@s.whatsapp.net"})
	for _, groupBy := range []string{"chat", "sender"} {
		d, err := scoped.DigestWith(ctx, DigestParams{Since: now.Add(-time.Hour), MaxGroups: 1, GroupBy: groupBy})
		if err != nil {
			t.Fatal(err)
		}
		text := scoped.FormatDigest(ctx, d, now.Add(-time.Hour))
		if strings.Contains(text, "Bob") {
			t.Fatalf("group_by=%s leaked a chat outside the token: %s", groupBy, text)
		}
		if !strings.Contains(text, "hello from Alice") {
			t.Fatalf("group_by=%s with one group slot must still show the token's chat: %s", groupBy, text)
		}
	}
}
