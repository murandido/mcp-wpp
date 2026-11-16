package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// Filters for the operator's chat list (the /access page).
const (
	AccessFilterAll     = "all"
	AccessFilterAllowed = "allowed"
	AccessFilterDenied  = "denied"
	AccessFilterPending = "pending" // chats matched by a pending access request
	AccessFilterGroups  = "groups"
	AccessFilterDirect  = "direct"
)

// ValidAccessFilter reports whether f is one of the AccessFilter* values.
func ValidAccessFilter(f string) bool {
	switch f {
	case AccessFilterAll, AccessFilterAllowed, AccessFilterDenied, AccessFilterPending, AccessFilterGroups, AccessFilterDirect:
		return true
	}
	return false
}

// AccessListOptions selects one page of the operator's chat list.
type AccessListOptions struct {
	Query  string // name or number, accent- and case-insensitive
	Filter string // an AccessFilter* value; "" means all
	Offset int
	Limit  int
}

// AccessListPage is one page of chats and the number that matched in all.
type AccessListPage struct {
	Chats []AccessEntry
	Total int
}

// ListAccessPage is ListAccess with a filter, an offset and a total, for
// the operator page. Matching runs in Go on the folded display name, the
// stored name and the JID, so it needs no FTS5 and handles accents. A query
// made only of phone-number characters ("+44 7700-900") matches on its
// digits. The cache holds hundreds of chats, not millions, so filtering
// the full list in memory is cheap and keeps the semantics of ListAccess.
func (s *Store) ListAccessPage(ctx context.Context, opts AccessListOptions) (AccessListPage, error) {
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.Offset < 0 {
		opts.Offset = 0
	}
	all, err := s.ListAccess(ctx, phoneQuery(opts.Query), 1<<30)
	if err != nil {
		return AccessListPage{}, err
	}
	var pending map[string]bool
	if opts.Filter == AccessFilterPending {
		reqs, err := s.ListAccessRequests(ctx, "pending")
		if err != nil {
			return AccessListPage{}, err
		}
		pending = map[string]bool{}
		for _, r := range reqs {
			for _, m := range r.Matches {
				pending[m.JID] = true
			}
		}
	}
	var page AccessListPage
	for _, e := range all {
		if !matchesAccessFilter(e, opts.Filter, pending) {
			continue
		}
		if page.Total >= opts.Offset && len(page.Chats) < opts.Limit {
			page.Chats = append(page.Chats, e)
		}
		page.Total++
	}
	return page, nil
}

func matchesAccessFilter(e AccessEntry, filter string, pending map[string]bool) bool {
	switch filter {
	case AccessFilterAllowed:
		return e.State == AccessAllowed
	case AccessFilterDenied:
		return e.State == AccessDenied
	case AccessFilterPending:
		return pending[e.JID]
	case AccessFilterGroups:
		return e.IsGroup
	case AccessFilterDirect:
		return strings.HasSuffix(e.JID, "@s.whatsapp.net") || strings.HasSuffix(e.JID, "@lid")
	}
	return true
}

// phoneQuery reduces a query made only of digits and phone punctuation to
// its digits, so "+44 7700 900001" finds 447700900001@s.whatsapp.net. Any
// other query is returned unchanged.
func phoneQuery(q string) string {
	q = strings.TrimSpace(q)
	digits := 0
	for _, r := range q {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case strings.ContainsRune("+-() .", r):
		default:
			return q
		}
	}
	if digits == 0 {
		return q
	}
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, q)
}

// ChatsExist returns the subset of jids that are cached chats, so a bulk
// operator action cannot create decisions for arbitrary strings.
func (s *Store) ChatsExist(ctx context.Context, jids []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, jid := range jids {
		var one int
		err := s.db.QueryRowContext(ctx, "SELECT 1 FROM chats WHERE jid = ?", jid).Scan(&one)
		if err == nil {
			out[jid] = true
		} else if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}
	return out, nil
}
