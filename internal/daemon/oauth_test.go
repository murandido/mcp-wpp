package daemon

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/murandido/mcp-wpp/internal/auth"
	"github.com/murandido/mcp-wpp/internal/oauth"
	"github.com/murandido/mcp-wpp/internal/store"
)

const oauthPublic = "https://wpp.test"

// oauthDaemon runs a guarded daemon with OAuth (when withOAuth) over a real
// store and an /mcp stub that reports the caller.
func oauthDaemon(t *testing.T, withOAuth bool) (string, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := Config{
		Tokens: st, Audit: st,
		MCPMount: func(mux *http.ServeMux) {
			mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
				id, _ := auth.FromContext(r.Context())
				writeJSON(w, http.StatusOK, map[string]any{"identity": id})
			})
		},
	}
	if withOAuth {
		srv, err := oauth.New(oauth.Config{PublicURL: oauthPublic, Store: st})
		if err != nil {
			t.Fatal(err)
		}
		cfg.OAuth = srv
	}
	return startGuardedServer(t, cfg), st
}

func mcpChallenge(t *testing.T, base, token string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/mcp", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := rawClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate")
}

func TestOAuth_ChallengeHeader(t *testing.T) {
	base, _ := oauthDaemon(t, true)
	meta := oauthPublic + "/.well-known/oauth-protected-resource/mcp"
	code, h := mcpChallenge(t, base, "")
	if want := `Bearer realm="wpp-mcp", resource_metadata="` + meta + `", scope="read"`; code != http.StatusUnauthorized || h != want {
		t.Fatalf("no credentials: %d %q, want %q", code, h, want)
	}
	unknown, _ := auth.NewToken()
	code, h = mcpChallenge(t, base, unknown)
	if want := `Bearer realm="wpp-mcp", resource_metadata="` + meta + `", scope="read", error="invalid_token"`; code != http.StatusUnauthorized || h != want {
		t.Fatalf("invalid token: %d %q", code, h)
	}
	// Other paths keep the plain challenge.
	req, _ := http.NewRequest(http.MethodGet, base+"/admin/access", nil)
	resp, err := rawClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != `Bearer realm="wpp-mcp"` {
		t.Fatalf("/admin challenge: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	// Without OAuth nothing changes.
	plain, _ := oauthDaemon(t, false)
	if code, h := mcpChallenge(t, plain, ""); code != http.StatusUnauthorized || h != `Bearer realm="wpp-mcp"` {
		t.Fatalf("without OAuth: %d %q", code, h)
	}
}

func TestOAuth_AudienceEnforcedAtMCP(t *testing.T) {
	base, st := oauthDaemon(t, true)
	plainBase, plainSt := oauthDaemon(t, false)
	ctx := context.Background()
	grant := func(s *store.Store, aud string) string {
		toks, err := s.CreateOAuthGrant(ctx, store.NewOAuthGrant{ClientID: "wppc_x", ClientName: "Claude", Scopes: []string{"read"}, Audience: aud})
		if err != nil {
			t.Fatal(err)
		}
		return toks.AccessToken
	}
	good := grant(st, oauthPublic+"/mcp")
	other := grant(st, "https://other.test/mcp")
	if code, _ := mcpChallenge(t, base, good); code != http.StatusOK {
		t.Fatalf("matching audience: %d", code)
	}
	if code, h := mcpChallenge(t, base, other); code != http.StatusUnauthorized || !strings.Contains(h, `error="invalid_token"`) {
		t.Fatalf("foreign audience: %d %q", code, h)
	}
	// Static tokens have no audience and keep working.
	_, static, err := st.CreateAPIToken(ctx, store.NewAPIToken{Name: "static", Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := mcpChallenge(t, base, static); code != http.StatusOK {
		t.Fatalf("static token: %d", code)
	}
	// A daemon without OAuth refuses every audience-bound token.
	if code, _ := mcpChallenge(t, plainBase, grant(plainSt, oauthPublic+"/mcp")); code != http.StatusUnauthorized {
		t.Fatalf("OAuth token without OAuth: %d", code)
	}
	// OAuth tokens never open the operator API.
	if code, _ := bearer(t, http.MethodGet, base+"/admin/oauth/pending", good, ""); code != http.StatusUnauthorized {
		t.Fatalf("access token on /admin: %d", code)
	}
}

func TestOAuth_PublicAndOperatorPaths(t *testing.T) {
	base, st := oauthDaemon(t, true)
	for _, p := range []string{
		oauth.PathResourceMetadata, oauth.PathResourceMetadataMCP, oauth.PathAuthServerMetadata,
	} {
		req, _ := http.NewRequest(http.MethodGet, base+p, nil)
		if got := status(t, rawClient, req); got != http.StatusOK {
			t.Errorf("%s: %d", p, got)
		}
	}
	// Unknown paths under /oauth stay closed.
	req, _ := http.NewRequest(http.MethodGet, base+"/oauth/other", nil)
	if got := status(t, rawClient, req); got != http.StatusUnauthorized {
		t.Errorf("/oauth/other: %d", got)
	}
	for _, p := range []string{"/admin/oauth/pending", "/admin/oauth/grants"} {
		req, _ := http.NewRequest(http.MethodGet, base+p, nil)
		if got := status(t, rawClient, req); got != http.StatusUnauthorized {
			t.Errorf("%s without bearer: %d", p, got)
		}
		if code, body := bearer(t, http.MethodGet, base+p, testToken, ""); code != http.StatusOK {
			t.Errorf("%s with bearer: %d %s", p, code, body)
		}
	}
	// Operator decisions are audited.
	if code, _ := bearer(t, http.MethodPost, base+"/admin/oauth/approve", testToken, `{"code":"ABCD-EFGH"}`); code != http.StatusBadRequest {
		t.Fatalf("approve unknown code: %d", code)
	}
	entries, err := st.ListAudit(context.Background(), store.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "POST /admin/oauth/approve" && strings.Contains(e.Detail, "code=ABCD-EFGH") && e.Outcome == store.OutcomeError {
			found = true
		}
	}
	if !found {
		t.Fatalf("approve not audited: %+v", entries)
	}
	// Public OAuth endpoints are not operator actions.
	req, _ = http.NewRequest(http.MethodPost, base+oauth.PathRegister, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	_ = status(t, rawClient, req)
	entries, _ = st.ListAudit(context.Background(), store.AuditFilter{})
	for _, e := range entries {
		if strings.Contains(e.Action, "/oauth/register") {
			t.Fatalf("public endpoint audited as operator: %+v", e)
		}
	}
}
