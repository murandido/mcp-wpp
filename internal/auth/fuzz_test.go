package auth

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

var validJID = regexp.MustCompile(`^[0-9A-Za-z._:\-]+@(s\.whatsapp\.net|g\.us|lid|broadcast|newsletter)$`)

func FuzzParseChats(f *testing.F) {
	for _, s := range []string{
		"447700900123", "+447700900123,1203630000000000@g.us", "", ",,", "a@evil.com", "123@lid, 123@lid",
		"x@s.whatsapp.net\n", "1@g.us,../etc", "+", "status@broadcast",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		chats, err := ParseChats(s)
		if err != nil {
			return
		}
		for i, c := range chats {
			if !validJID.MatchString(c) {
				t.Fatalf("ParseChats(%q) accepted %q", s, c)
			}
			if slices.Contains(chats[:i], c) {
				t.Fatalf("ParseChats(%q) returned %q twice", s, c)
			}
		}
	})
}

func FuzzParseScopes(f *testing.F) {
	for _, s := range []string{"read", "read,send", "send", "", "READ, send", "admin", "read,read"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		scopes, err := ParseScopes(s)
		if err != nil {
			return
		}
		if !slices.Contains(scopes, ScopeRead) || !slices.IsSorted(scopes) || len(scopes) > 2 {
			t.Fatalf("ParseScopes(%q) = %v", s, scopes)
		}
		for _, sc := range scopes {
			if sc != ScopeRead && sc != ScopeSend {
				t.Fatalf("ParseScopes(%q) accepted %q", s, sc)
			}
		}
	})
}

func FuzzLooksLikeToken(f *testing.F) {
	f.Add(TokenPrefix + strings.Repeat("a", 64))
	f.Add(TokenPrefix + strings.Repeat("A", 64))
	f.Add("Bearer x")
	f.Fuzz(func(t *testing.T, s string) {
		if LooksLikeToken(s) && (len(s) != len(TokenPrefix)+64 || !strings.HasPrefix(s, TokenPrefix) || strings.ContainsAny(s, " \r\n")) {
			t.Fatalf("LooksLikeToken accepted %q", s)
		}
	})
}
