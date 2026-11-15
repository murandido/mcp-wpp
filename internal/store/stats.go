package store

import (
	"context"
	"fmt"
	"time"
)

// Counts are aggregate figures for /admin/metrics. They are numbers only,
// never names or JIDs.
type Counts struct {
	ChatsCached    int
	ChatsVisible   int
	OutboxPending  int
	AccessRequests int
}

// Counts returns the cache and consent figures. It always reads the whole
// cache (it is an operator view, not an MCP read), and counts visible chats
// with the same accessFilter the scoped store applies.
func (s *Store) Counts(ctx context.Context) (Counts, error) {
	var c Counts
	err := s.db.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM chats),
		(SELECT count(*) FROM chats WHERE `+accessFilter("jid")+`),
		(SELECT count(*) FROM outbox WHERE status = 'pending' AND expires_at >= ?),
		(SELECT count(*) FROM access_requests WHERE status = 'pending')`, time.Now().UTC()).
		Scan(&c.ChatsCached, &c.ChatsVisible, &c.OutboxPending, &c.AccessRequests)
	if err != nil {
		return Counts{}, fmt.Errorf("count store: %w", err)
	}
	return c, nil
}
