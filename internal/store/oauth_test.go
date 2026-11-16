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

func TestOAuthSchema_MigratesOldTokensTable(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate the pre-OAuth api_tokens table with a token in it.
	for _, q := range []string{
		"DROP TABLE api_tokens",
		strings.TrimSpace(tokensSchema),
	} {
		if _, err := st.DB().Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := st.CreateAPIToken(context.Background(), NewAPIToken{Name: "legacy", Scopes: []string{"read"}}); err == nil {
		t.Fatal("expected the old table to lack the new columns")
	}
	if _, err := st.DB().Exec("INSERT INTO api_tokens (name, token_hash, scopes, created_at) VALUES ('legacy', x'00', 'read', ?)", time.Now()); err != nil {
		t.Fatal(err)
	}
	st.Close()

	st, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, col := range []string{"audience", "grant_id"} {
		if ok, err := hasColumn(st.DB(), "api_tokens", col); err != nil || !ok {
			t.Fatalf("column %s missing after migration: %v", col, err)
		}
	}
	list, err := st.ListAPITokens(context.Background())
	if err != nil || len(list) != 1 || list[0].Name != "legacy" || list[0].Audience != "" {
		t.Fatalf("legacy token after migration: %+v %v", list, err)
	}
}

func TestOAuthGrant_RevokeKillsTokens(t *testing.T) {
	st := openFileStore(t)
	ctx := context.Background()
	toks, err := st.CreateOAuthGrant(ctx, NewOAuthGrant{ClientID: "wppc_a", ClientName: "Claude\x1b; rm", Scopes: []string{"read", "send"}, Chats: []string{"447700000001"}, Audience: "https://wpp.test/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	at, err := st.VerifyAPIToken(ctx, toks.AccessToken)
	if err != nil || at.GrantID != toks.Grant.ID || at.Audience != "https://wpp.test/mcp" || at.Name != "oauth:Claude-rm#"+toks.Grant.ID {
		t.Fatalf("access token: %+v %v", at, err)
	}
	if !strings.HasPrefix(toks.RefreshToken, RefreshTokenPrefix) || auth.LooksLikeToken(toks.RefreshToken) {
		t.Fatal("a refresh token must never pass as a bearer token")
	}
	var stored []byte
	if err := st.DB().QueryRow("SELECT token_hash FROM oauth_refresh_tokens WHERE grant_id = ?", toks.Grant.ID).Scan(&stored); err != nil || bytes.Contains(stored, []byte(toks.RefreshToken)) || len(stored) != 32 {
		t.Fatalf("refresh token stored in the clear? %v", err)
	}
	// OAuth tokens do not count against the static token cap.
	var n int
	_ = st.DB().QueryRow("SELECT count(*) FROM api_tokens WHERE grant_id IS NULL").Scan(&n)
	if n != 0 {
		t.Fatal("grant token counted as static")
	}
	if _, err := st.RevokeOAuthGrant(ctx, toks.Grant.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.VerifyAPIToken(ctx, toks.AccessToken); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("access token after revoke: %v", err)
	}
	if _, err := st.RefreshOAuthGrant(ctx, toks.RefreshToken, "wppc_a", nil); !errors.Is(err, ErrOAuthGrantInvalid) {
		t.Fatalf("refresh after revoke: %v", err)
	}
	if _, err := st.RevokeOAuthGrant(ctx, "nope", ""); err == nil {
		t.Fatal("unknown grant revoked")
	}
}

func TestOAuthGrant_RefreshScopeNarrowing(t *testing.T) {
	st := openFileStore(t)
	ctx := context.Background()
	toks, err := st.CreateOAuthGrant(ctx, NewOAuthGrant{ClientID: "c", ClientName: "C", Scopes: []string{"read"}, Audience: "https://wpp.test/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.RefreshOAuthGrant(ctx, toks.RefreshToken, "c", []string{"read", "send"}); !errors.Is(err, ErrOAuthScope) {
		t.Fatalf("widening refresh: %v", err)
	}
	// A refused widening does not burn the refresh token.
	next, err := st.RefreshOAuthGrant(ctx, toks.RefreshToken, "c", []string{"read"})
	if err != nil || strings.Join(next.Scopes, ",") != "read" {
		t.Fatalf("refresh: %+v %v", next, err)
	}
	// The previous access token was replaced.
	if _, err := st.VerifyAPIToken(ctx, toks.AccessToken); err == nil {
		t.Fatal("superseded access token still valid")
	}
}

func TestOAuthClients_CapAndCache(t *testing.T) {
	st := openFileStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.Add(-2 * time.Hour)
	for i := 0; i < maxOAuthClients; i++ {
		c := OAuthClient{ClientID: "https://c.test/" + strings.Repeat("x", i+1), Kind: OAuthClientCIMD, ClientName: "c", RedirectURIs: []string{"https://claude.ai/api/mcp/auth_callback"}, CreatedAt: old, FetchedAt: &old}
		if err := st.PutOAuthClient(ctx, c, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	// Stale cache rows make room for a new client.
	if err := st.PutOAuthClient(ctx, OAuthClient{ClientID: "wppc_new", Kind: OAuthClientDCR, ClientName: "n", RedirectURIs: []string{"x"}, CreatedAt: now}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if c, err := st.GetOAuthClient(ctx, "wppc_new"); err != nil || c.Kind != OAuthClientDCR || c.RedirectURIs[0] != "x" {
		t.Fatalf("get: %+v %v", c, err)
	}
	if n, _ := st.CountOAuthClients(ctx, OAuthClientCIMD); n != 0 {
		t.Fatalf("stale CIMD rows kept: %d", n)
	}
}
