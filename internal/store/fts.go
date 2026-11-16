package store

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/murandido/mcp-wpp/internal/textfold"
)

// Full-text search over message text with SQLite FTS5. The index is an
// external-content table over messages(content), kept in sync by triggers,
// with diacritics removed so "nao" finds "não". Builds without FTS5 (plain
// `go test` without the sqlite_fts5 tag) fall back to LIKE.

const ftsSchema = `
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
	content, content='messages', content_rowid='rowid',
	tokenize='unicode61 remove_diacritics 2'
);
CREATE TRIGGER IF NOT EXISTS messages_fts_ai AFTER INSERT ON messages BEGIN
	INSERT INTO messages_fts(rowid, content) VALUES (new.rowid, COALESCE(new.content, ''));
END;
CREATE TRIGGER IF NOT EXISTS messages_fts_ad AFTER DELETE ON messages BEGIN
	INSERT INTO messages_fts(messages_fts, rowid, content) VALUES ('delete', old.rowid, COALESCE(old.content, ''));
END;
CREATE TRIGGER IF NOT EXISTS messages_fts_au AFTER UPDATE OF content ON messages BEGIN
	INSERT INTO messages_fts(messages_fts, rowid, content) VALUES ('delete', old.rowid, COALESCE(old.content, ''));
	INSERT INTO messages_fts(rowid, content) VALUES (new.rowid, COALESCE(new.content, ''));
END;
`

// minFTSQuery is the shortest query sent to the index; shorter ones use LIKE
// so a one- or two-letter search still finds substrings.
const minFTSQuery = 3

// enableFTS creates (and on first creation backfills) the index. It returns
// false when this SQLite build lacks FTS5.
func enableFTS(db *sql.DB) (bool, error) {
	var exists int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name = 'messages_fts'").Scan(&exists); err != nil {
		return false, err
	}
	if _, err := db.Exec(ftsSchema); err != nil {
		if strings.Contains(err.Error(), "no such module: fts5") {
			return false, nil
		}
		return false, fmt.Errorf("create search index: %w", err)
	}
	if exists == 0 {
		if _, err := db.Exec("INSERT INTO messages_fts(messages_fts) VALUES ('rebuild')"); err != nil {
			return false, fmt.Errorf("build search index: %w", err)
		}
	}
	return true, nil
}

// ftsMatchQuery turns free text into an FTS5 query: every word must appear,
// as a prefix, so "reuni amanh" finds "reunião amanhã". Words are quoted, so
// FTS5 operators typed by a user or a model are matched literally.
func ftsMatchQuery(q string) string {
	var terms []string
	for _, w := range strings.Fields(q) {
		w = strings.ReplaceAll(w, `"`, "")
		if w != "" {
			terms = append(terms, `"`+w+`"*`)
		}
	}
	return strings.Join(terms, " ")
}

// foldMatch is a LIKE condition matching col against a foldPattern
// argument: a case- and accent-insensitive substring match. It is the
// fallback when FTS5 is missing or the query is too short for the index.
// unaccent_lower is registered on every connection by the crypto connector.
func foldMatch(col string) string {
	return textfold.SQLFunc + "(" + col + `) LIKE ? ESCAPE '\'`
}

// foldPattern is the LIKE argument for foldMatch: q folded, with LIKE
// wildcards escaped so they match literally.
func foldPattern(q string) string {
	return "%" + escapeLike(textfold.Fold(q)) + "%"
}

// FTSEnabled reports whether full-text search is available. Without it,
// list_messages matches substrings (still case- and accent-insensitive).
func (s *Store) FTSEnabled() bool { return s.fts }
