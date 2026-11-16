package store

import (
	"context"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/auth"
)

func TestOutbox_RecordsCreator(t *testing.T) {
	s := openFileStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	tok, _, err := s.CreateAPIToken(ctx, NewAPIToken{Name: "connector", Scopes: []string{auth.ScopeRead, auth.ScopeSend}})
	if err != nil {
		t.Fatal(err)
	}
	tokenCtx := auth.WithIdentity(ctx, tok.Identity())

	byOperator, err := s.CreateProposal(ctx, "send_message", "{}", "a")
	if err != nil || byOperator.CreatedBy != "operator" || byOperator.CreatorTokenID != 0 {
		t.Fatalf("operator proposal: %+v %v", byOperator, err)
	}
	byToken, err := s.CreateProposal(tokenCtx, "send_message", "{}", "b")
	if err != nil || byToken.CreatedBy != "token:connector" || byToken.CreatorTokenID != tok.ID {
		t.Fatalf("token proposal: %+v %v", byToken, err)
	}
	scheduled, err := s.ScheduleMessage(WithCreator(ctx, CreatorOperatorCLI), "schedule_message", "{}", "c", now.Add(time.Hour), now)
	if err != nil || scheduled.CreatedBy != CreatorOperatorCLI {
		t.Fatalf("operator schedule: %+v %v", scheduled, err)
	}
	for _, want := range []*Proposal{byOperator, byToken, scheduled} {
		got, err := s.GetProposal(ctx, want.ID)
		if err != nil || got.CreatedBy != want.CreatedBy || got.CreatorTokenID != want.CreatorTokenID {
			t.Fatalf("stored creator of #%d: %+v %v", want.ID, got, err)
		}
	}

	if revoked, err := s.CreatorRevoked(ctx, byToken); err != nil || revoked {
		t.Fatalf("active token: %v %v", revoked, err)
	}
	if _, err := s.RevokeAPIToken(ctx, "connector"); err != nil {
		t.Fatal(err)
	}
	if revoked, err := s.CreatorRevoked(ctx, byToken); err != nil || !revoked {
		t.Fatalf("revoked token: %v %v", revoked, err)
	}
	if revoked, _ := s.CreatorRevoked(ctx, byOperator); revoked {
		t.Fatal("operator items are never refused")
	}
	// A token that no longer exists counts as revoked.
	if revoked, _ := s.CreatorRevoked(ctx, &Proposal{CreatorTokenID: 99999}); !revoked {
		t.Fatal("unknown creator token must count as revoked")
	}
}

func TestOutbox_MigratesCreatorColumns(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// An outbox made by v0.9 (send_at, no creator).
	for _, stmt := range []string{
		"DROP TABLE outbox",
		`CREATE TABLE outbox (
			id INTEGER PRIMARY KEY AUTOINCREMENT, tool TEXT NOT NULL, args_json TEXT NOT NULL, summary TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending'
			CHECK (status IN ('pending', 'scheduled', 'sent', 'failed', 'rejected', 'expired', 'missed', 'cancelled')),
			result TEXT, created_at TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL, decided_at TIMESTAMP, send_at TIMESTAMP)`,
		"INSERT INTO outbox (id, tool, args_json, summary, status, created_at, expires_at) VALUES (3, 'send_message', '{}', 'old', 'sent', '2026-01-01 10:00:00+00:00', '2026-01-01 10:15:00+00:00')",
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	ctx := context.Background()
	if old, err := s.GetProposal(ctx, 3); err != nil || old.CreatedBy != "" || old.Summary != "old" {
		t.Fatalf("old row: %+v %v", old, err)
	}
	if p, err := s.CreateProposal(ctx, "send_message", "{}", "new"); err != nil || p.CreatedBy != "operator" {
		t.Fatalf("new row: %+v %v", p, err)
	}
	if err := migrateOutboxCreator(s.db); err != nil {
		t.Fatal(err)
	}
}
