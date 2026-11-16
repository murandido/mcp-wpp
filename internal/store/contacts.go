package store

import (
	"context"
	"database/sql"
	"strings"
)

// contactNameExpr coalesces the whatsmeow_contacts name columns in preference
// order: the saved address-book name first, then push name, first name, and
// business name. NULLIF folds empty strings into NULL so COALESCE skips them.
const contactNameExpr = `COALESCE(NULLIF(full_name,''), NULLIF(push_name,''), NULLIF(first_name,''), NULLIF(business_name,''))`

// ContactName returns the synced address-book name for a JID from the
// whatsmeow_contacts table, or "" when the contact is unknown or the
// whatsmeow store is unavailable. LID JIDs are resolved to phone JIDs first.
func (s *Store) ContactName(jid string) string {
	if s.whatsmeowDB == nil {
		return ""
	}
	for _, candidate := range s.contactJIDs(s.ResolveLIDToJID(jid)) {
		var name sql.NullString
		err := s.whatsmeowDB.QueryRow(
			`SELECT `+contactNameExpr+` FROM whatsmeow_contacts WHERE their_jid = ?`, candidate).Scan(&name)
		if err == nil && name.Valid && name.String != "" {
			return name.String
		}
	}
	return ""
}

// searchContactNames returns address-book contacts whose name contains query
// (case- and accent-insensitive) or whose JID contains it, as a jid ->
// display-name map. Empty when the whatsmeow store is unavailable.
func (s *Store) searchContactNames(query string) map[string]string {
	out := map[string]string{}
	if s.whatsmeowDB == nil {
		return out
	}
	name := foldPattern(query)
	rows, err := s.whatsmeowDB.Query(`
		SELECT their_jid, `+contactNameExpr+` AS name
		FROM whatsmeow_contacts
		WHERE (their_jid LIKE '%@s.whatsapp.net' OR their_jid LIKE '%@lid')
		  AND (`+foldMatch("full_name")+` OR `+foldMatch("push_name")+`
		    OR `+foldMatch("first_name")+` OR `+foldMatch("business_name")+`
		    OR their_jid LIKE ?)
		LIMIT 50`, name, name, name, name, "%"+query+"%")
	if err != nil {
		return out
	}
	type match struct{ jid, name string }
	var matches []match
	for rows.Next() {
		var jid string
		var name sql.NullString
		if err := rows.Scan(&jid, &name); err != nil || !name.Valid || name.String == "" {
			continue
		}
		matches = append(matches, match{jid, name.String})
	}
	// Close before resolving LIDs: the resolution queries the same database,
	// and a pool of one connection would deadlock on the open cursor.
	rows.Close()
	for _, m := range matches {
		// LID-keyed contacts are reported under their phone JID, which is
		// how chats are cached; unresolved LIDs keep their LID form.
		jid := s.ResolveLIDToJID(m.jid)
		if _, seen := out[jid]; !seen || !strings.HasSuffix(jid, "@lid") {
			out[jid] = m.name
		}
	}
	return out
}

// isNumberName reports whether a chat name is only digits: the chat's phone
// number, or a LID user part, which is what WhatsApp leaves on many 1:1 chats.
func isNumberName(name, _ string) bool {
	digits := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9':
			return r
		case r == '+' || r == ' ' || r == '-' || r == '(' || r == ')' || r == '.':
			return -1
		}
		return 'x'
	}, name)
	return !strings.Contains(digits, "x")
}

// displayName returns the best human name for a chat: the cached chat name,
// unless it is empty or just the number, in which case the synced address
// book (saved, business or pushed name) wins.
func (s *Store) displayName(ctx context.Context, jid, name string) string {
	if !isNumberName(name, jid) || strings.HasSuffix(jid, "@g.us") {
		return name
	}
	if book := s.addressBookName(ctx, jid); book != "" {
		return book
	}
	return name
}
