package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/murandido/mcp-wpp/internal/auth"
)

// OAuth grants. internal/oauth runs the authorization flow; this file keeps
// what must survive a restart: registered clients, grants and their refresh
// tokens. An OAuth access token is an ordinary api_tokens row with an
// audience and a grant_id, so the HTTP guard verifies it like any client
// token. Only SHA-256 hashes of access and refresh tokens are stored.
//
// Authorization codes and pending approvals live in the daemon's memory.

const oauthSchema = `
CREATE TABLE IF NOT EXISTS oauth_clients (
	client_id     TEXT PRIMARY KEY,
	kind          TEXT NOT NULL,
	client_name   TEXT NOT NULL,
	redirect_uris TEXT NOT NULL,
	created_at    TIMESTAMP NOT NULL,
	fetched_at    TIMESTAMP
);
CREATE TABLE IF NOT EXISTS oauth_grants (
	id                 TEXT PRIMARY KEY,
	client_id          TEXT NOT NULL,
	client_name        TEXT NOT NULL,
	redirect_uri       TEXT NOT NULL,
	scopes             TEXT NOT NULL,
	chats              TEXT,
	audience           TEXT NOT NULL,
	refresh_ttl_s      INTEGER NOT NULL,
	refresh_expires_at TIMESTAMP NOT NULL,
	created_at         TIMESTAMP NOT NULL,
	last_used_at       TIMESTAMP,
	revoked_at         TIMESTAMP,
	revoke_reason      TEXT
);
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
	token_hash BLOB PRIMARY KEY,
	grant_id   TEXT NOT NULL REFERENCES oauth_grants(id) ON DELETE CASCADE,
	created_at TIMESTAMP NOT NULL,
	used_at    TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_grant ON oauth_refresh_tokens(grant_id);
`

// applyOAuthSchema creates the OAuth tables and adds api_tokens.audience and
// api_tokens.grant_id when they are missing. Idempotent.
func applyOAuthSchema(db *sql.DB) error {
	if _, err := db.Exec(oauthSchema); err != nil {
		return fmt.Errorf("apply oauth schema: %w", err)
	}
	for _, col := range []string{"audience", "grant_id"} {
		has, err := hasColumn(db, "api_tokens", col)
		if err != nil {
			return err
		}
		if !has {
			if _, err := db.Exec("ALTER TABLE api_tokens ADD COLUMN " + col + " TEXT"); err != nil {
				return fmt.Errorf("add column api_tokens.%s: %w", col, err)
			}
		}
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_api_tokens_grant ON api_tokens(grant_id)"); err != nil {
		return fmt.Errorf("index api_tokens.grant_id: %w", err)
	}
	return nil
}

// OAuth limits and lifetimes.
const (
	// OAuthAccessTTL is the lifetime of an OAuth access token.
	OAuthAccessTTL = time.Hour
	// OAuthDefaultRefreshTTL is how long a grant's refresh token lasts
	// without use; every refresh slides it forward.
	OAuthDefaultRefreshTTL = 30 * 24 * time.Hour
	// OAuthMaxRefreshTTL caps what the operator may choose.
	OAuthMaxRefreshTTL = 365 * 24 * time.Hour
	// maxOAuthClients bounds the client table (DCR plus cached CIMD).
	maxOAuthClients = 200
	// maxOAuthGrants bounds the active grants.
	maxOAuthGrants = 50
	// oauthTokenRetention is how long revoked or expired OAuth rows are
	// kept for `oauth grants` and `token list` before they are pruned.
	oauthTokenRetention = 7 * 24 * time.Hour
)

// Client kinds.
const (
	OAuthClientDCR  = "dcr"
	OAuthClientCIMD = "cimd"
)

// RefreshTokenPrefix starts every refresh token. It differs from
// auth.TokenPrefix so a refresh token is never accepted as a bearer token.
const RefreshTokenPrefix = "wppmcpr_" //nolint:gosec // G101: a public prefix, not a credential

var refreshPattern = regexp.MustCompile(`^` + RefreshTokenPrefix + `[0-9a-f]{64}$`)

// Errors.
var (
	// ErrOAuthGrantInvalid covers unknown, used, expired and revoked
	// refresh tokens alike.
	ErrOAuthGrantInvalid = errors.New("invalid grant")
	// ErrOAuthLimit means a table cap was reached.
	ErrOAuthLimit = errors.New("too many OAuth clients or grants")
	// ErrOAuthScope means a refresh asked for a scope the grant lacks.
	ErrOAuthScope = errors.New("scope was not granted")
)

// OAuthClient is a registered (DCR) client or a cached Client ID Metadata
// Document.
type OAuthClient struct {
	ClientID     string     `json:"client_id"`
	Kind         string     `json:"kind"`
	ClientName   string     `json:"client_name"`
	RedirectURIs []string   `json:"redirect_uris"`
	CreatedAt    time.Time  `json:"created_at"`
	FetchedAt    *time.Time `json:"fetched_at,omitempty"`
}

// PutOAuthClient inserts or replaces a client. A new client is refused when
// the table is full, after stale CIMD cache rows have been dropped.
func (s *Store) PutOAuthClient(ctx context.Context, c OAuthClient, cimdTTL time.Duration) error {
	raw, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM oauth_clients WHERE client_id = ?", c.ClientID).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		now := time.Now().UTC()
		if _, err := tx.ExecContext(ctx, "DELETE FROM oauth_clients WHERE kind = ? AND fetched_at < ?", OAuthClientCIMD, now.Add(-cimdTTL)); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM oauth_clients").Scan(&n); err != nil {
			return err
		}
		if n >= maxOAuthClients {
			return ErrOAuthLimit
		}
	}
	var fetched any
	if c.FetchedAt != nil {
		fetched = c.FetchedAt.UTC()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO oauth_clients (client_id, kind, client_name, redirect_uris, created_at, fetched_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(client_id) DO UPDATE SET client_name = excluded.client_name, redirect_uris = excluded.redirect_uris, fetched_at = excluded.fetched_at`,
		c.ClientID, c.Kind, c.ClientName, string(raw), c.CreatedAt.UTC(), fetched); err != nil {
		return fmt.Errorf("store oauth client: %w", err)
	}
	return tx.Commit()
}

// GetOAuthClient returns the client with id, or sql.ErrNoRows.
func (s *Store) GetOAuthClient(ctx context.Context, id string) (OAuthClient, error) {
	var (
		c       OAuthClient
		uris    string
		fetched sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, "SELECT client_id, kind, client_name, redirect_uris, created_at, fetched_at FROM oauth_clients WHERE client_id = ?", id).
		Scan(&c.ClientID, &c.Kind, &c.ClientName, &uris, &c.CreatedAt, &fetched)
	if err != nil {
		return OAuthClient{}, err
	}
	if err := json.Unmarshal([]byte(uris), &c.RedirectURIs); err != nil {
		return OAuthClient{}, fmt.Errorf("oauth client %q: corrupt redirect_uris: %w", id, err)
	}
	if fetched.Valid {
		t := fetched.Time
		c.FetchedAt = &t
	}
	return c, nil
}

// CountOAuthClients returns the number of clients of kind.
func (s *Store) CountOAuthClients(ctx context.Context, kind string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM oauth_clients WHERE kind = ?", kind).Scan(&n)
	return n, err
}

// OAuthGrant is an approved connection: one client, the scopes and chats
// the operator approved, and the current refresh token.
type OAuthGrant struct {
	ID               string     `json:"id"`
	ClientID         string     `json:"client_id"`
	ClientName       string     `json:"client_name"`
	RedirectURI      string     `json:"redirect_uri"`
	Scopes           []string   `json:"scopes"`
	Chats            []string   `json:"chats,omitempty"`
	Audience         string     `json:"audience"`
	RefreshTTL       int64      `json:"refresh_ttl_s"`
	RefreshExpiresAt time.Time  `json:"refresh_expires_at"`
	CreatedAt        time.Time  `json:"created_at"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevokeReason     string     `json:"revoke_reason,omitempty"`
}

// Status is "active", "expired" or "revoked" at now.
func (g OAuthGrant) Status(now time.Time) string {
	switch {
	case g.RevokedAt != nil:
		return "revoked"
	case !now.Before(g.RefreshExpiresAt):
		return "expired"
	}
	return "active"
}

// NewOAuthGrant describes a grant to create.
type NewOAuthGrant struct {
	ClientID    string
	ClientName  string
	RedirectURI string
	Scopes      []string
	Chats       []string
	Audience    string
	RefreshTTL  time.Duration
}

// OAuthTokens is what a token endpoint returns.
type OAuthTokens struct {
	Grant        OAuthGrant
	AccessToken  string
	RefreshToken string
	Scopes       []string
	ExpiresIn    int
}

const grantCols = "id, client_id, client_name, redirect_uri, scopes, COALESCE(chats, ''), audience, refresh_ttl_s, refresh_expires_at, created_at, last_used_at, revoked_at, COALESCE(revoke_reason, '')"

func scanGrant(row interface{ Scan(...any) error }) (OAuthGrant, error) {
	var (
		g             OAuthGrant
		scopes, chats string
		used, revoked sql.NullTime
	)
	if err := row.Scan(&g.ID, &g.ClientID, &g.ClientName, &g.RedirectURI, &scopes, &chats, &g.Audience, &g.RefreshTTL,
		&g.RefreshExpiresAt, &g.CreatedAt, &used, &revoked, &g.RevokeReason); err != nil {
		return g, err
	}
	g.Scopes = strings.Split(scopes, ",")
	if chats != "" {
		if err := json.Unmarshal([]byte(chats), &g.Chats); err != nil {
			return g, fmt.Errorf("grant %s: corrupt chat list: %w", g.ID, err)
		}
		if g.Chats == nil {
			g.Chats = []string{}
		}
	}
	if used.Valid {
		t := used.Time
		g.LastUsedAt = &t
	}
	if revoked.Valid {
		t := revoked.Time
		g.RevokedAt = &t
	}
	return g, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func newRefreshToken() (string, error) {
	h, err := randomHex(32)
	if err != nil {
		return "", err
	}
	return RefreshTokenPrefix + h, nil
}

func hashSecret(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

var unsafeNameChars = regexp.MustCompile(`[^A-Za-z0-9._ -]+`)

// oauthTokenName is the api_tokens name of a grant's access token.
func oauthTokenName(clientName, grantID string) string {
	n := strings.TrimSpace(unsafeNameChars.ReplaceAllString(clientName, ""))
	n = strings.ReplaceAll(n, " ", "-")
	if len(n) > 40 {
		n = n[:40]
	}
	if n == "" {
		n = "client"
	}
	return "oauth:" + n + "#" + grantID
}

// insertAccessToken replaces the grant's access token with a fresh one.
// Older access tokens of the grant are deleted: a refresh supersedes them.
func insertAccessToken(ctx context.Context, tx *sql.Tx, g OAuthGrant, scopes []string, now time.Time) (string, error) {
	plain, err := auth.NewToken()
	if err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM api_tokens WHERE grant_id = ?", g.ID); err != nil {
		return "", fmt.Errorf("replace access token: %w", err)
	}
	var chatsCol any
	if g.Chats != nil {
		raw, _ := json.Marshal(g.Chats)
		chatsCol = string(raw)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO api_tokens (name, token_hash, scopes, chats, created_at, expires_at, audience, grant_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		oauthTokenName(g.ClientName, g.ID), auth.HashToken(plain), strings.Join(scopes, ","), chatsCol, now, now.Add(OAuthAccessTTL), g.Audience, g.ID); err != nil {
		return "", fmt.Errorf("create access token: %w", err)
	}
	return plain, nil
}

func insertRefreshToken(ctx context.Context, tx *sql.Tx, grantID string, now time.Time) (string, error) {
	plain, err := newRefreshToken()
	if err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO oauth_refresh_tokens (token_hash, grant_id, created_at) VALUES (?, ?, ?)", hashSecret(plain), grantID, now); err != nil {
		return "", fmt.Errorf("create refresh token: %w", err)
	}
	return plain, nil
}

// pruneOAuth drops grants (with their tokens) that have been revoked or
// expired for longer than oauthTokenRetention.
func pruneOAuth(ctx context.Context, tx *sql.Tx, now time.Time) error {
	cutoff := now.Add(-oauthTokenRetention)
	rows, err := tx.QueryContext(ctx, "SELECT id FROM oauth_grants WHERE (revoked_at IS NOT NULL AND revoked_at < ?) OR refresh_expires_at < ?", cutoff, cutoff)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		for _, q := range []string{
			"DELETE FROM api_tokens WHERE grant_id = ?",
			"DELETE FROM oauth_refresh_tokens WHERE grant_id = ?",
			"DELETE FROM oauth_grants WHERE id = ?",
		} {
			if _, err := tx.ExecContext(ctx, q, id); err != nil {
				return err
			}
		}
	}
	return nil
}

// CreateOAuthGrant stores an approved grant and returns its first access
// and refresh tokens.
func (s *Store) CreateOAuthGrant(ctx context.Context, in NewOAuthGrant) (OAuthTokens, error) {
	scopes, err := auth.ParseScopes(strings.Join(in.Scopes, ","))
	if err != nil {
		return OAuthTokens{}, err
	}
	chats := in.Chats
	if chats != nil {
		if chats, err = auth.ParseChats(strings.Join(in.Chats, ",")); err != nil {
			return OAuthTokens{}, err
		}
		if chats == nil {
			chats = []string{}
		}
	}
	if in.ClientID == "" || in.Audience == "" {
		return OAuthTokens{}, errors.New("grant needs a client and an audience")
	}
	ttl := in.RefreshTTL
	if ttl <= 0 {
		ttl = OAuthDefaultRefreshTTL
	}
	if ttl > OAuthMaxRefreshTTL {
		return OAuthTokens{}, fmt.Errorf("refresh lifetime is at most %d days", int(OAuthMaxRefreshTTL.Hours()/24))
	}
	id, err := randomHex(6)
	if err != nil {
		return OAuthTokens{}, err
	}
	now := time.Now().UTC()
	g := OAuthGrant{
		ID: id, ClientID: in.ClientID, ClientName: in.ClientName, RedirectURI: in.RedirectURI,
		Scopes: scopes, Chats: chats, Audience: in.Audience, RefreshTTL: int64(ttl / time.Second),
		RefreshExpiresAt: now.Add(ttl), CreatedAt: now,
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OAuthTokens{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := pruneOAuth(ctx, tx, now); err != nil {
		return OAuthTokens{}, fmt.Errorf("prune oauth: %w", err)
	}
	var active int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM oauth_grants WHERE revoked_at IS NULL AND refresh_expires_at > ?", now).Scan(&active); err != nil {
		return OAuthTokens{}, err
	}
	if active >= maxOAuthGrants {
		return OAuthTokens{}, fmt.Errorf("%w: %d active grants; revoke some with `wpp-mcp oauth revoke`", ErrOAuthLimit, active)
	}
	var chatsCol any
	if chats != nil {
		raw, _ := json.Marshal(chats)
		chatsCol = string(raw)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO oauth_grants (id, client_id, client_name, redirect_uri, scopes, chats, audience, refresh_ttl_s, refresh_expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		g.ID, g.ClientID, g.ClientName, g.RedirectURI, strings.Join(scopes, ","), chatsCol, g.Audience, g.RefreshTTL, g.RefreshExpiresAt, now); err != nil {
		return OAuthTokens{}, fmt.Errorf("create grant: %w", err)
	}
	access, err := insertAccessToken(ctx, tx, g, scopes, now)
	if err != nil {
		return OAuthTokens{}, err
	}
	refresh, err := insertRefreshToken(ctx, tx, g.ID, now)
	if err != nil {
		return OAuthTokens{}, err
	}
	if err := tx.Commit(); err != nil {
		return OAuthTokens{}, err
	}
	return OAuthTokens{Grant: g, AccessToken: access, RefreshToken: refresh, Scopes: scopes, ExpiresIn: int(OAuthAccessTTL.Seconds())}, nil
}

// RefreshOAuthGrant redeems a refresh token: it is marked used, and a new
// refresh token and access token are issued (rotation). Presenting a refresh
// token that was already used revokes the whole grant, with its access
// tokens, since either the client or an attacker holds a stolen copy.
//
// clientID must be the grant's client. scopes, when non-empty, narrows the
// new access token to a subset of the grant's scopes. Every failure is
// ErrOAuthGrantInvalid, except a scope outside the grant (an error that
// wraps ErrOAuthScope).
func (s *Store) RefreshOAuthGrant(ctx context.Context, refreshPlain, clientID string, scopes []string) (OAuthTokens, error) {
	if !refreshPattern.MatchString(refreshPlain) {
		return OAuthTokens{}, ErrOAuthGrantInvalid
	}
	want := hashSecret(refreshPlain)
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OAuthTokens{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var (
		stored  []byte
		grantID string
		usedAt  sql.NullTime
	)
	// The lookup is by the SHA-256 of a 256-bit random secret, so the index
	// probe reveals nothing useful; the comparison below is constant time.
	err = tx.QueryRowContext(ctx, "SELECT token_hash, grant_id, used_at FROM oauth_refresh_tokens WHERE token_hash = ?", want).Scan(&stored, &grantID, &usedAt)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && subtle.ConstantTimeCompare(stored, want) != 1) {
		return OAuthTokens{}, ErrOAuthGrantInvalid
	}
	if err != nil {
		return OAuthTokens{}, err
	}
	g, err := scanGrant(tx.QueryRowContext(ctx, "SELECT "+grantCols+" FROM oauth_grants WHERE id = ?", grantID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return OAuthTokens{}, ErrOAuthGrantInvalid
		}
		return OAuthTokens{}, err
	}
	if g.ClientID != clientID {
		// Another client presenting this token: refuse without touching
		// the grant, which the real client may still use.
		return OAuthTokens{}, ErrOAuthGrantInvalid
	}
	if usedAt.Valid {
		if g.RevokedAt == nil {
			if err := revokeGrantTx(ctx, tx, g.ID, "refresh token reuse", now); err != nil {
				return OAuthTokens{}, err
			}
			if err := tx.Commit(); err != nil {
				return OAuthTokens{}, err
			}
		}
		return OAuthTokens{}, ErrOAuthGrantInvalid
	}
	if g.Status(now) != "active" {
		return OAuthTokens{}, ErrOAuthGrantInvalid
	}
	issued := g.Scopes
	if len(scopes) > 0 {
		for _, sc := range scopes {
			found := false
			for _, have := range g.Scopes {
				if sc == have {
					found = true
				}
			}
			if !found {
				return OAuthTokens{}, fmt.Errorf("%w: %q", ErrOAuthScope, sc)
			}
		}
		if issued, err = auth.ParseScopes(strings.Join(scopes, ",")); err != nil {
			return OAuthTokens{}, err
		}
	}
	res, err := tx.ExecContext(ctx, "UPDATE oauth_refresh_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL", now, want)
	if err != nil {
		return OAuthTokens{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return OAuthTokens{}, ErrOAuthGrantInvalid
	}
	g.RefreshExpiresAt = now.Add(time.Duration(g.RefreshTTL) * time.Second)
	g.LastUsedAt = &now
	if _, err := tx.ExecContext(ctx, "UPDATE oauth_grants SET refresh_expires_at = ?, last_used_at = ? WHERE id = ?", g.RefreshExpiresAt, now, g.ID); err != nil {
		return OAuthTokens{}, err
	}
	access, err := insertAccessToken(ctx, tx, g, issued, now)
	if err != nil {
		return OAuthTokens{}, err
	}
	refresh, err := insertRefreshToken(ctx, tx, g.ID, now)
	if err != nil {
		return OAuthTokens{}, err
	}
	if err := tx.Commit(); err != nil {
		return OAuthTokens{}, err
	}
	return OAuthTokens{Grant: g, AccessToken: access, RefreshToken: refresh, Scopes: issued, ExpiresIn: int(OAuthAccessTTL.Seconds())}, nil
}

func revokeGrantTx(ctx context.Context, tx *sql.Tx, id, reason string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, "UPDATE oauth_grants SET revoked_at = ?, revoke_reason = ? WHERE id = ? AND revoked_at IS NULL", now, reason, id); err != nil {
		return fmt.Errorf("revoke grant: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE api_tokens SET revoked_at = ? WHERE grant_id = ? AND revoked_at IS NULL", now, id); err != nil {
		return fmt.Errorf("revoke grant tokens: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE oauth_refresh_tokens SET used_at = ? WHERE grant_id = ? AND used_at IS NULL", now, id); err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}
	return nil
}

// RevokeOAuthGrant revokes a grant, its refresh token and every access
// token it issued. Revoking an already revoked grant is not an error.
func (s *Store) RevokeOAuthGrant(ctx context.Context, id, reason string) (OAuthGrant, error) {
	id = strings.TrimSpace(id)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OAuthGrant{}, err
	}
	defer func() { _ = tx.Rollback() }()
	g, err := scanGrant(tx.QueryRowContext(ctx, "SELECT "+grantCols+" FROM oauth_grants WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return OAuthGrant{}, fmt.Errorf("no grant %q", id)
	}
	if err != nil {
		return OAuthGrant{}, err
	}
	now := time.Now().UTC()
	if err := revokeGrantTx(ctx, tx, id, reason, now); err != nil {
		return OAuthGrant{}, err
	}
	if err := tx.Commit(); err != nil {
		return OAuthGrant{}, err
	}
	if g.RevokedAt == nil {
		g.RevokedAt, g.RevokeReason = &now, reason
	}
	return g, nil
}

// RevokeOAuthToken implements RFC 7009 for a client: a refresh token
// revokes its whole grant, an access token only itself. Only tokens of a
// grant belonging to clientID are affected; anything else is silently
// ignored, as the RFC asks.
func (s *Store) RevokeOAuthToken(ctx context.Context, token, clientID string) error {
	now := time.Now().UTC()
	switch {
	case refreshPattern.MatchString(token):
		var grantID, owner string
		err := s.db.QueryRowContext(ctx, `SELECT g.id, g.client_id FROM oauth_refresh_tokens r JOIN oauth_grants g ON g.id = r.grant_id WHERE r.token_hash = ?`, hashSecret(token)).Scan(&grantID, &owner)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && clientID != "" && owner != clientID) {
			return nil
		}
		if err != nil {
			return err
		}
		_, err = s.RevokeOAuthGrant(ctx, grantID, "revoked by client")
		return err
	case auth.LooksLikeToken(token):
		var owner string
		err := s.db.QueryRowContext(ctx, `SELECT g.client_id FROM api_tokens t JOIN oauth_grants g ON g.id = t.grant_id WHERE t.token_hash = ?`, auth.HashToken(token)).Scan(&owner)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && clientID != "" && owner != clientID) {
			return nil
		}
		if err != nil {
			return err
		}
		_, err = s.db.ExecContext(ctx, "UPDATE api_tokens SET revoked_at = ? WHERE token_hash = ? AND grant_id IS NOT NULL AND revoked_at IS NULL", now, auth.HashToken(token))
		return err
	}
	return nil
}

// ListOAuthGrants returns every grant, newest first.
func (s *Store) ListOAuthGrants(ctx context.Context) ([]OAuthGrant, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+grantCols+" FROM oauth_grants ORDER BY created_at DESC")
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}
	defer rows.Close()
	var out []OAuthGrant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
