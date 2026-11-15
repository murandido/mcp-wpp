package auth

import (
	"context"
	"strings"
	"testing"
)

func TestNewToken_FormatAndHash(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewToken()
	if a == b {
		t.Fatal("two tokens are equal")
	}
	if !strings.HasPrefix(a, TokenPrefix) || len(a) != len(TokenPrefix)+64 || !LooksLikeToken(a) {
		t.Fatalf("token format: %q", a)
	}
	for _, bad := range []string{"", TokenPrefix, a[:len(a)-1], strings.ToUpper(a), "x" + a, a + "0", "test-token-0123456789abcdef"} {
		if LooksLikeToken(bad) {
			t.Errorf("LooksLikeToken(%q) = true", bad)
		}
	}
	if h := HashToken(a); len(h) != 32 || string(h) == string(HashToken(b)) {
		t.Fatalf("hash: %x", h)
	}
}

func TestParseScopes(t *testing.T) {
	for in, want := range map[string]string{"read": "read", "send,read": "read,send", " READ , send ,read": "read,send"} {
		got, err := ParseScopes(in)
		if err != nil || strings.Join(got, ",") != want {
			t.Errorf("ParseScopes(%q) = %v, %v; want %s", in, got, err, want)
		}
	}
	for _, in := range []string{"", "send", "read,admin", "write"} {
		if _, err := ParseScopes(in); err == nil {
			t.Errorf("ParseScopes(%q) accepted", in)
		}
	}
}

func TestNormalizeChat(t *testing.T) {
	for in, want := range map[string]string{
		"+447700000001":               "447700000001@s.whatsapp.net",
		"447700000001@s.whatsapp.net": "447700000001@s.whatsapp.net",
		"120363000000000000@g.us":     "120363000000000000@g.us",
	} {
		if got, err := NormalizeChat(in); err != nil || got != want {
			t.Errorf("NormalizeChat(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "Alice", "x'@g.us", "1@evil.com", "a b@g.us"} {
		if _, err := NormalizeChat(in); err == nil {
			t.Errorf("NormalizeChat(%q) accepted", in)
		}
	}
	if got, err := ParseChats(" , "); err != nil || got != nil {
		t.Fatalf("empty chat list: %v %v", got, err)
	}
}

func TestIdentity(t *testing.T) {
	op := Operator("bearer")
	if !op.Has(ScopeSend) || op.Actor() != "operator" || op.ChatRestriction() != nil {
		t.Fatalf("operator: %+v", op)
	}
	tok := Identity{Kind: KindToken, TokenID: 3, Name: "connector", Scopes: []string{ScopeRead}, Chats: []string{"1@s.whatsapp.net"}}
	if tok.Has(ScopeSend) || !tok.Has(ScopeRead) || tok.Actor() != "token:connector" || len(tok.ChatRestriction()) != 1 {
		t.Fatalf("token: %+v", tok)
	}
	if !Caller(context.Background()).IsOperator() {
		t.Fatal("a context without identity is in-process, hence the operator")
	}
	if got := Caller(WithIdentity(context.Background(), tok)); got.Name != "connector" {
		t.Fatalf("Caller: %+v", got)
	}
}
