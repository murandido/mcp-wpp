package store

import (
	"context"
	"testing"
)

func TestCounts(t *testing.T) {
	s := openAccessStore(t)
	if _, err := s.db.Exec(outboxSchema); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c, err := s.Counts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c.ChatsCached != 4 || c.ChatsVisible != 0 || c.OutboxPending != 0 {
		t.Fatalf("fresh counts: %+v", c)
	}
	if err := s.SetChatAccess(ctx, aliceJID, AccessAllowed, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProposal(ctx, "send_message", "{}", "summary"); err != nil {
		t.Fatal(err)
	}
	if c, _ = s.Counts(ctx); c.ChatsVisible != 1 || c.OutboxPending != 1 {
		t.Fatalf("after allow and proposal: %+v", c)
	}
	if err := s.SetAccessMode(ctx, AccessAll); err != nil {
		t.Fatal(err)
	}
	if err := s.SetChatAccess(ctx, bobJID, AccessDenied, ""); err != nil {
		t.Fatal(err)
	}
	if c, _ = s.Counts(ctx); c.ChatsVisible != 3 {
		t.Fatalf("mode all with one denied: %+v", c)
	}
}
