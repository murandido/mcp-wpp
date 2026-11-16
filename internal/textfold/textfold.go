// Package textfold folds text for case- and accent-insensitive matching:
// "JOÃO" and "joao" fold to the same string.
package textfold

import (
	"strings"
	"unicode"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// SQLFunc is the name of the deterministic SQLite function that applies
// Fold. The crypto connector registers it on every connection, so store
// queries can match with `unaccent_lower(column) LIKE ?` against a pattern
// folded in Go.
const SQLFunc = "unaccent_lower"

// Fold lowercases s and strips combining marks (diacritics), keeping
// everything else: "Reunião às 10h" → "reuniao as 10h".
func Fold(s string) string {
	t := transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)
	out, _, err := transform.String(t, strings.ToLower(s))
	if err != nil {
		return strings.ToLower(s)
	}
	return out
}

// SQL is the implementation of SQLFunc. Text and blobs are folded as text;
// anything else (numbers, NULL) is returned unchanged. The driver may pass
// NULL as an empty value, so NULL can fold to an empty string: it never matches a
// non-empty search pattern either way.
func SQL(v any) any {
	switch x := v.(type) {
	case string:
		return Fold(x)
	case []byte:
		return Fold(string(x))
	default:
		return v
	}
}
