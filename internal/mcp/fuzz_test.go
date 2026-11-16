package mcp

import (
	"net/url"
	"strings"
	"testing"
)

func FuzzParseMediaURI(f *testing.F) {
	for _, s := range []string{
		"whatsapp://media/447700900123%40s.whatsapp.net/3EB0ABC", "whatsapp://media/a/b/c", "whatsapp://media//x",
		"whatsapp://media/x/", "whatsapp://media/%zz/x", "file:///etc/passwd", "", "whatsapp://media/",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		chat, id, err := parseMediaURI(raw)
		if err != nil {
			return
		}
		if chat == "" || id == "" || strings.Contains(id, "/") {
			t.Fatalf("parseMediaURI(%q) = %q, %q", raw, chat, id)
		}
		// Rebuilding the URI from the parts gives the same parts back.
		again := mediaURIPrefix + url.PathEscape(chat) + "/" + id
		c2, id2, err := parseMediaURI(again)
		if err != nil || c2 != chat || id2 != id {
			t.Fatalf("round trip of %q via %q: %q %q %v", raw, again, c2, id2, err)
		}
	})
}

func FuzzNormalizeRecipientToChatJID(f *testing.F) {
	for _, s := range []string{"+447700900123", "447700900123@s.whatsapp.net", "", "abc", "+"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got := normalizeRecipientToChatJID(raw)
		if got != "" && !strings.Contains(got, "@") {
			t.Fatalf("normalizeRecipientToChatJID(%q) = %q is not a JID", raw, got)
		}
	})
}
