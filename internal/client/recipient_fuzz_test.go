package client

import (
	"strings"
	"testing"
)

func FuzzNormalizeRecipient(f *testing.F) {
	for _, s := range []string{"447700900123", "+447700900123", " +44 7700 900123 ", "", "+", "++1", "1203630000000000@g.us", "abc", "12-34", "١٢٣"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := NormalizeRecipient(raw)
		if err != nil {
			if !strings.HasPrefix(err.Error(), "recipient: ") {
				t.Fatalf("error %q lacks the recipient prefix", err)
			}
			return
		}
		if strings.Contains(got, "@") {
			if got != strings.TrimSpace(raw) {
				t.Fatalf("JID %q changed to %q", raw, got)
			}
			return
		}
		if got == "" || !isAllDigits(got) {
			t.Fatalf("NormalizeRecipient(%q) = %q is not bare digits", raw, got)
		}
	})
}
