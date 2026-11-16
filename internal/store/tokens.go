package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/murandido/mcp-wpp/internal/auth"
)

// Client API tokens. The operator token in <store>/token keeps full access;
// these tokens are for MCP clients (/mcp only) and can be scoped, limited to
// some chats, given an expiry and revoked without restarting the daemon.
// Only a SHA-256 of each token is stored; the plaintext is shown once.

const tokensSchema = `
CREATE TABLE IF NOT EXISTS api_tokens (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	name         TEXT NOT NULL UNIQUE,
	token_hash   BLOB NOT NULL UNIQUE,
	scopes       TEXT NOT NULL,
	chats        TEXT,
	created_at   TIMESTAMP NOT NULL,
	expires_at   TIMESTAMP,
	last_used_at TIMESTAMP,
	revoked_at   TIMESTAMP
);
`

// tokenTouchInterval bounds how often last_used_at is written.
const tokenTouchInterval = time.Minute

// maxTokens bounds the table so a verification scan stays trivial.
const maxTokens = 200

var tokenNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// APIToken is a client token as the operator sees it. It never holds the
// token itself.
type APIToken struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	Chats      []string   `json:"chats,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	// Audience, when set, is the only resource the token is valid for
	// (OAuth access tokens; RFC 8707). Static tokens have none.
	Audience string `json:"audience,omitempty"`
	// GrantID links an OAuth access token to its grant.
	GrantID string `json:"grant_id,omitempty"`
	hash    []byte
}

// Status is "active", "expired" or "revoked" at now.
func (t APIToken) Status(now time.Time) string {
	switch {
	case t.RevokedAt != nil:
		return "revoked"
	case t.ExpiresAt != nil && !now.Before(*t.ExpiresAt):
		return "expired"
	}
	return "active"
}

// Identity is the caller a valid token authenticates as.
func (t APIToken) Identity() auth.Identity {
	return auth.Identity{Kind: auth.KindToken, TokenID: t.ID, Name: t.Name, Scopes: t.Scopes, Chats: t.Chats}
}

// ErrTokenInvalid is the single error for unknown, revoked and expired
// tokens.
var ErrTokenInvalid = errors.New("invalid token")

// NewAPIToken describes a token to create.
type NewAPIToken struct {
	Name      string     `json:"name"`
	Scopes    []string   `json:"scopes"`
	Chats     []string   `json:"chats,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// CreateAPIToken stores a new token and returns it with its plaintext, which
// is not kept anywhere.
func (s *Store) CreateAPIToken(ctx context.Context, in NewAPIToken) (APIToken, string, error) {
	name := strings.TrimSpace(in.Name)
	if !tokenNamePattern.MatchString(name) {
		return APIToken{}, "", errors.New("token name must be 1-64 letters, digits, '.', '_' or '-', starting with a letter or digit")
	}
	if _, err := strconv.ParseInt(name, 10, 64); err == nil {
		return APIToken{}, "", errors.New("token name must not be a number (numbers refer to token IDs)")
	}
	scopes, err := auth.ParseScopes(strings.Join(in.Scopes, ","))
	if err != nil {
		return APIToken{}, "", err
	}
	chats, err := auth.ParseChats(strings.Join(in.Chats, ","))
	if err != nil {
		return APIToken{}, "", err
	}
	now := time.Now().UTC()
	if in.ExpiresAt != nil && !in.ExpiresAt.After(now) {
		return APIToken{}, "", errors.New("expiry must be in the future")
	}
	var n int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM api_tokens WHERE grant_id IS NULL").Scan(&n); err != nil {
		return APIToken{}, "", fmt.Errorf("count tokens: %w", err)
	}
	if n >= maxTokens {
		return APIToken{}, "", fmt.Errorf("there are already %d tokens; revoke and delete old ones first", n)
	}
	plain, err := auth.NewToken()
	if err != nil {
		return APIToken{}, "", err
	}
	var chatsCol any
	if len(chats) > 0 {
		raw, _ := json.Marshal(chats)
		chatsCol = string(raw)
	}
	var expires any
	if in.ExpiresAt != nil {
		expires = in.ExpiresAt.UTC()
	}
	res, err := s.db.ExecContext(ctx,
		"INSERT INTO api_tokens (name, token_hash, scopes, chats, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
		name, auth.HashToken(plain), strings.Join(scopes, ","), chatsCol, now, expires)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return APIToken{}, "", fmt.Errorf("a token named %q already exists", name)
		}
		return APIToken{}, "", fmt.Errorf("create token: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return APIToken{}, "", err
	}
	t := APIToken{ID: id, Name: name, Scopes: scopes, Chats: chats, CreatedAt: now}
	if in.ExpiresAt != nil {
		e := in.ExpiresAt.UTC()
		t.ExpiresAt = &e
	}
	return t, plain, nil
}

const tokCols = "id, name, token_hash, scopes, COALESCE(chats, ''), created_at, expires_at, last_used_at, revoked_at, COALESCE(audience, ''), COALESCE(grant_id, '')"

func scanToken(row interface{ Scan(...any) error }) (APIToken, error) {
	var (
		t                        APIToken
		scopes, chats            string
		expires, used, revokedAt sql.NullTime
	)
	if err := row.Scan(&t.ID, &t.Name, &t.hash, &scopes, &chats, &t.CreatedAt, &expires, &used, &revokedAt, &t.Audience, &t.GrantID); err != nil {
		return t, err
	}
	t.Scopes = strings.Split(scopes, ",")
	if chats != "" {
		if err := json.Unmarshal([]byte(chats), &t.Chats); err != nil {
			return t, fmt.Errorf("token %d: corrupt chat list: %w", t.ID, err)
		}
		if t.Chats == nil {
			t.Chats = []string{}
		}
	}
	for _, p := range []struct {
		src sql.NullTime
		dst **time.Time
	}{{expires, &t.ExpiresAt}, {used, &t.LastUsedAt}, {revokedAt, &t.RevokedAt}} {
		if p.src.Valid {
			v := p.src.Time
			*p.dst = &v
		}
	}
	return t, nil
}

// ListAPITokens returns every token, newest first.
func (s *Store) ListAPITokens(ctx context.Context) ([]APIToken, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+tokCols+" FROM api_tokens ORDER BY id DESC")
	if err != nil {
		return nil, fmt.Errorf("list tokens: %w", err)
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken revokes the token named ref, or with ID ref. Revoking is
// immediate: the next request with that token is refused.
func (s *Store) RevokeAPIToken(ctx context.Context, ref string) (APIToken, error) {
	ref = strings.TrimSpace(ref)
	q, arg := "SELECT "+tokCols+" FROM api_tokens WHERE name = ?", any(ref)
	if id, err := strconv.ParseInt(ref, 10, 64); err == nil {
		q, arg = "SELECT "+tokCols+" FROM api_tokens WHERE id = ?", id
	}
	t, err := scanToken(s.db.QueryRowContext(ctx, q, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return APIToken{}, fmt.Errorf("no token %q", ref)
	}
	if err != nil {
		return APIToken{}, err
	}
	if t.RevokedAt != nil {
		return t, nil
	}
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, "UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", now, t.ID); err != nil {
		return APIToken{}, fmt.Errorf("revoke token: %w", err)
	}
	t.RevokedAt = &now
	return t, nil
}

// VerifyAPIToken returns the active token matching plain. Unknown, revoked
// and expired tokens all return ErrTokenInvalid. The hash comparison runs in
// constant time over every candidate. last_used_at is refreshed at most
// once per tokenTouchInterval.
func (s *Store) VerifyAPIToken(ctx context.Context, plain string) (APIToken, error) {
	if !auth.LooksLikeToken(plain) {
		return APIToken{}, ErrTokenInvalid
	}
	want := auth.HashToken(plain)
	rows, err := s.db.QueryContext(ctx, "SELECT "+tokCols+" FROM api_tokens WHERE revoked_at IS NULL")
	if err != nil {
		return APIToken{}, fmt.Errorf("verify token: %w", err)
	}
	var (
		match APIToken
		found bool
	)
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			rows.Close()
			return APIToken{}, err
		}
		if subtle.ConstantTimeCompare(t.hash, want) == 1 {
			match, found = t, true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return APIToken{}, err
	}
	now := time.Now().UTC()
	if !found || match.Status(now) != "active" {
		return APIToken{}, ErrTokenInvalid
	}
	if match.LastUsedAt == nil || now.Sub(*match.LastUsedAt) >= tokenTouchInterval {
		// Best effort: a failed bookkeeping write must not refuse the call.
		_, _ = s.db.ExecContext(ctx, "UPDATE api_tokens SET last_used_at = ? WHERE id = ?", now, match.ID)
		match.LastUsedAt = &now
	}
	return match, nil
}

// ScopedTo is Scoped further narrowed to chats, the chat set of a client
// token: a chat is visible only when the access policy allows it and it is
// in chats. A nil chats is the same as Scoped. The narrowing is applied in
// SQL wherever the access policy is.
func (s *Store) ScopedTo(chats []string) *Store {
	c := s.Scoped()
	if chats != nil {
		c.tokenChats = slices.Clone(chats)
		if c.tokenChats == nil {
			c.tokenChats = []string{}
		}
	}
	return c
}

// tokenFilter returns " AND <col> IN (...)" for a view narrowed by a token,
// "" otherwise. The JIDs were validated by auth.NormalizeChat when the token
// was created and are quoted again here, so the clause needs no arguments
// and splices into any query like accessFilter.
func (s *Store) tokenFilter(col string) string {
	if s.tokenChats == nil {
		return ""
	}
	if len(s.tokenChats) == 0 {
		return " AND 0"
	}
	quoted := make([]string, len(s.tokenChats))
	for i, j := range s.tokenChats {
		quoted[i] = "'" + strings.ReplaceAll(j, "'", "''") + "'"
	}
	return fmt.Sprintf(" AND %s IN (%s)", col, strings.Join(quoted, ","))
}

// tokenAllows reports whether the token narrowing admits jid.
func (s *Store) tokenAllows(jid string) bool {
	return s.tokenChats == nil || slices.Contains(s.tokenChats, jid)
}
