// Package auth carries the authenticated caller from the HTTP guard to the
// MCP handlers and defines the format of client API tokens.
//
// There are two kinds of caller:
//
//   - the operator, who holds the token in <store>/token (or WPP_MCP_TOKEN)
//     or a browser session minted from it. The operator has full access and
//     is the only caller accepted on /admin/* and the operator pages.
//   - a client token, created with `wpp-mcp token create`, accepted on /mcp
//     only. It carries scopes (read, send) and an optional set of chats that
//     narrows, never widens, what the access policy allows.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Kind tells the operator apart from client tokens.
type Kind string

// Caller kinds.
const (
	KindOperator Kind = "operator"
	KindToken    Kind = "token"
)

// Scopes a client token can hold.
const (
	ScopeRead = "read"
	ScopeSend = "send"
)

// TokenPrefix starts every client token so secret scanners can match it.
const TokenPrefix = "wppmcp_"

// tokenBytes is the amount of randomness in a client token.
const tokenBytes = 32

// Identity is the authenticated caller of one request.
type Identity struct {
	Kind Kind `json:"kind"`
	// TokenID and Name identify a client token; both are zero for the
	// operator.
	TokenID int64  `json:"token_id,omitempty"`
	Name    string `json:"name,omitempty"`
	// Scopes held by a client token. The operator holds every scope.
	Scopes []string `json:"scopes,omitempty"`
	// Chats, when non-nil, restricts a client token to these chat JIDs on
	// top of the access policy.
	Chats []string `json:"chats,omitempty"`
	// Via records how the operator authenticated: "bearer" or "session".
	Via string `json:"via,omitempty"`
}

// Operator returns the operator identity.
func Operator(via string) Identity { return Identity{Kind: KindOperator, Via: via} }

// IsOperator reports whether the caller holds the operator token.
func (i Identity) IsOperator() bool { return i.Kind == KindOperator }

// Has reports whether the caller holds scope.
func (i Identity) Has(scope string) bool {
	return i.IsOperator() || slices.Contains(i.Scopes, scope)
}

// Actor is the caller's name in the audit log: "operator" or
// "token:<name>".
func (i Identity) Actor() string {
	if i.IsOperator() {
		return string(KindOperator)
	}
	return "token:" + i.Name
}

// ChatRestriction returns the token's chat set, or nil when the caller is
// limited by the access policy alone.
func (i Identity) ChatRestriction() []string {
	if i.IsOperator() {
		return nil
	}
	return i.Chats
}

type identityKey struct{}

// WithIdentity attaches id to ctx.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// FromContext returns the caller attached by the HTTP guard. In-process
// callers (tests, smoke, outbox approval) carry none; see Caller.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

// Caller returns the identity on ctx, or the operator when there is none.
// Only the daemon's HTTP guard admits external callers, and it always sets
// an identity, so a context without one comes from inside the process.
func Caller(ctx context.Context) Identity {
	if id, ok := FromContext(ctx); ok {
		return id
	}
	return Operator("internal")
}

// NewToken returns a fresh client token: TokenPrefix followed by 32 random
// bytes in hex.
func NewToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return TokenPrefix + hex.EncodeToString(b), nil
}

var tokenPattern = regexp.MustCompile(`^` + TokenPrefix + `[0-9a-f]{64}$`)

// LooksLikeToken reports whether s has the client token format. It says
// nothing about whether the token exists.
func LooksLikeToken(s string) bool { return tokenPattern.MatchString(s) }

// HashToken returns the SHA-256 of a token. Only the hash is stored.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// ParseScopes parses a comma-separated scope list. "read" is always
// required: a token that can send must also be able to read the chat it
// writes to.
func ParseScopes(s string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" || seen[p] {
			continue
		}
		if p != ScopeRead && p != ScopeSend {
			return nil, fmt.Errorf("unknown scope %q (use read or read,send)", p)
		}
		seen[p] = true
		out = append(out, p)
	}
	if !seen[ScopeRead] {
		return nil, errors.New("scope must include read (use read or read,send)")
	}
	slices.Sort(out)
	return out, nil
}

var jidPattern = regexp.MustCompile(`^[0-9A-Za-z._:\-]+@(s\.whatsapp\.net|g\.us|lid|broadcast|newsletter)$`)

// NormalizeChat turns a chat reference into a JID: phone digits (an optional
// leading + is dropped) become <digits>@s.whatsapp.net, and anything else
// must already be a well-formed WhatsApp JID.
func NormalizeChat(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	digits := strings.TrimPrefix(ref, "+")
	if digits != "" && strings.Trim(digits, "0123456789") == "" {
		return digits + "@s.whatsapp.net", nil
	}
	if !jidPattern.MatchString(ref) {
		return "", fmt.Errorf("invalid chat %q: use a JID such as 5511999999999@s.whatsapp.net or 1203...@g.us, or phone digits", ref)
	}
	return ref, nil
}

// ParseChats parses a comma-separated chat list with NormalizeChat. An empty
// list returns nil (no restriction).
func ParseChats(s string) ([]string, error) {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if strings.TrimSpace(p) == "" {
			continue
		}
		jid, err := NormalizeChat(p)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(out, jid) {
			out = append(out, jid)
		}
	}
	return out, nil
}
