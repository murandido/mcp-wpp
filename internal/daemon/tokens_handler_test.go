package daemon

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/auth"
	"github.com/murandido/mcp-wpp/internal/store"
)

// tokenDaemon runs a daemon over a real store with client tokens and audit
// on, and an /mcp stub that echoes the caller identity it was handed.
func tokenDaemon(t *testing.T) (string, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.StoreChat(accAlice, "Alice", time.Now()); err != nil {
		t.Fatal(err)
	}
	base := startGuardedServer(t, Config{
		Access: st, Tokens: st, Audit: st,
		MCPMount: func(mux *http.ServeMux) {
			mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
				id, ok := auth.FromContext(r.Context())
				writeJSON(w, http.StatusOK, map[string]any{"ok": ok, "identity": id})
			})
		},
	})
	return base, st
}

func bearer(t *testing.T, method, u, token, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, u, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := rawClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func TestTokens_IdentityReachesMCPHandlers(t *testing.T) {
	base, st := tokenDaemon(t)
	ctx := context.Background()

	code, body := bearer(t, http.MethodPost, base+"/mcp", testToken, "")
	if code != http.StatusOK || !strings.Contains(body, `"kind":"operator"`) || !strings.Contains(body, `"via":"bearer"`) {
		t.Fatalf("operator on /mcp: %d %s", code, body)
	}

	tok, secret, err := st.CreateAPIToken(ctx, store.NewAPIToken{Name: "claude-ai", Scopes: []string{"read"}, Chats: []string{accAlice}})
	if err != nil {
		t.Fatal(err)
	}
	code, body = bearer(t, http.MethodPost, base+"/mcp", secret, "")
	var got struct {
		OK       bool          `json:"ok"`
		Identity auth.Identity `json:"identity"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil || code != http.StatusOK || !got.OK {
		t.Fatalf("client token on /mcp: %d %s", code, body)
	}
	if got.Identity.Kind != auth.KindToken || got.Identity.TokenID != tok.ID || got.Identity.Name != "claude-ai" ||
		got.Identity.Has(auth.ScopeSend) || len(got.Identity.Chats) != 1 || got.Identity.Chats[0] != accAlice {
		t.Fatalf("identity: %+v", got.Identity)
	}

	// Client tokens never reach the operator surface.
	if code, _ := bearer(t, http.MethodGet, base+"/admin/access", secret, ""); code != http.StatusUnauthorized {
		t.Fatalf("client token on /admin: %d", code)
	}
	if code, _ := bearer(t, http.MethodGet, base+"/access", secret, ""); code != http.StatusUnauthorized {
		t.Fatalf("client token on a page: %d", code)
	}
}

func TestTokens_RejectionsAreIdentical(t *testing.T) {
	base, st := tokenDaemon(t)
	ctx := context.Background()
	_, revoked, _ := st.CreateAPIToken(ctx, store.NewAPIToken{Name: "old", Scopes: []string{"read"}})
	if _, err := st.RevokeAPIToken(ctx, "old"); err != nil {
		t.Fatal(err)
	}
	expiring, expired, _ := st.CreateAPIToken(ctx, store.NewAPIToken{Name: "short", Scopes: []string{"read"}})
	if _, err := st.DB().Exec("UPDATE api_tokens SET expires_at = ? WHERE id = ?", time.Now().UTC().Add(-time.Minute), expiring.ID); err != nil {
		t.Fatal(err)
	}
	unknown, _ := auth.NewToken()

	var bodies []string
	for name, tok := range map[string]string{"revoked": revoked, "expired": expired, "unknown": unknown, "garbage": "not-a-token-at-all"} {
		code, body := bearer(t, http.MethodPost, base+"/mcp", tok, "")
		if code != http.StatusUnauthorized {
			t.Fatalf("%s token: %d %s", name, code, body)
		}
		bodies = append(bodies, body)
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("rejections differ: %q vs %q", b, bodies[0])
		}
	}
}

func TestTokens_AdminAPIAndAudit(t *testing.T) {
	base, st := tokenDaemon(t)
	ctx := context.Background()

	code, body := bearer(t, http.MethodPost, base+"/admin/tokens", testToken, `{"name":"phone","scopes":["read","send"],"chats":["447700000001"]}`)
	var created struct {
		Token  store.APIToken `json:"token"`
		Secret string         `json:"secret"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil || code != http.StatusOK || !auth.LooksLikeToken(created.Secret) {
		t.Fatalf("create: %d %s", code, body)
	}
	if created.Token.Chats[0] != accAlice {
		t.Fatalf("phone digits not normalised: %v", created.Token.Chats)
	}
	code, body = bearer(t, http.MethodGet, base+"/admin/tokens", testToken, "")
	if code != http.StatusOK || strings.Contains(body, created.Secret) || !strings.Contains(body, `"status":"active"`) {
		t.Fatalf("list: %d %s", code, body)
	}
	if code, body := bearer(t, http.MethodPost, base+"/admin/tokens/phone/revoke", testToken, ""); code != http.StatusOK {
		t.Fatalf("revoke: %d %s", code, body)
	}
	if code, _ := bearer(t, http.MethodPost, base+"/mcp", created.Secret, ""); code != http.StatusUnauthorized {
		t.Fatalf("revoked token still accepted: %d", code)
	}

	// An access change is audited with its chat and state, never its note.
	if code, body := bearer(t, http.MethodPost, base+"/admin/access/chat", testToken, `{"jid":"`+accAlice+`","state":"allowed","note":"private note"}`); code != http.StatusOK {
		t.Fatalf("access chat: %d %s", code, body)
	}
	// A failed admin action is audited as an error.
	if code, _ := bearer(t, http.MethodPost, base+"/admin/tokens/nope/revoke", testToken, ""); code != http.StatusBadRequest {
		t.Fatalf("revoking a missing token: %d", code)
	}

	entries, err := st.ListAudit(ctx, store.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	byAction := map[string][]store.AuditEntry{}
	for _, e := range entries {
		if e.Kind != store.AuditAdmin || e.Actor != "operator" {
			t.Errorf("admin entry: %+v", e)
		}
		if strings.Contains(e.Detail, "private note") || strings.Contains(e.Detail, created.Secret) {
			t.Errorf("audit leaked request content: %+v", e)
		}
		byAction[e.Action] = append(byAction[e.Action], e)
	}
	if es := byAction["POST /admin/tokens"]; len(es) != 1 || es[0].Outcome != store.OutcomeOK || !strings.Contains(es[0].Detail, "name=phone") {
		t.Errorf("token create entry: %+v", es)
	}
	if es := byAction["POST /admin/tokens/{ref}/revoke"]; len(es) != 2 || es[0].Outcome != store.OutcomeError || es[1].Outcome != store.OutcomeOK {
		t.Errorf("token revoke entries: %+v", es)
	}
	if es := byAction["POST /admin/access/chat"]; len(es) != 1 || es[0].ChatJID != accAlice || es[0].Detail != "state=allowed" {
		t.Errorf("access entry: %+v", es)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Action, "GET ") {
			t.Errorf("reads must not be audited as admin actions: %+v", e)
		}
	}

	code, body = bearer(t, http.MethodGet, base+"/admin/audit?actor=operator&limit=2", testToken, "")
	if code != http.StatusOK || strings.Count(body, `"action"`) != 2 {
		t.Fatalf("audit API: %d %s", code, body)
	}
}
