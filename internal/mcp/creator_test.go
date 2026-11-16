package mcp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/auth"
	"github.com/murandido/mcp-wpp/internal/store"
)

// realToken creates a client token in st and returns a request context
// carrying it.
func realToken(t *testing.T, st *store.Store, name string) context.Context {
	t.Helper()
	tok, _, err := st.CreateAPIToken(context.Background(), store.NewAPIToken{Name: name, Scopes: []string{auth.ScopeRead, auth.ScopeSend}})
	if err != nil {
		t.Fatal(err)
	}
	return auth.WithIdentity(context.Background(), tok.Identity())
}

func TestCreator_RecordedAndRevokedTokenRefused(t *testing.T) {
	ctx := context.Background()
	s, st := policyServer(t, true)
	tctx := realToken(t, st, "connector")

	res := callToolAs(t, s, tctx, "send_message", map[string]any{"recipient": visibleJID, "message": "hi"})
	id := proposalID(t, res)
	p, err := st.GetProposal(ctx, id)
	if err != nil || p.CreatedBy != "token:connector" || p.CreatorTokenID == 0 {
		t.Fatalf("creator not recorded: %+v %v", p, err)
	}
	opID := proposalID(t, callToolDirect(t, s, "send_message", map[string]any{"recipient": visibleJID, "message": "hi"}))
	if op, _ := st.GetProposal(ctx, opID); op.CreatedBy != "operator" {
		t.Fatalf("operator creator: %+v", op)
	}

	if _, err := st.RevokeAPIToken(ctx, "connector"); err != nil {
		t.Fatal(err)
	}
	got, err := s.ApproveProposal(ctx, id)
	if err != nil || got.Status != store.OutboxFailed || !strings.Contains(got.Result, "revoked") {
		t.Fatalf("approval of a revoked token's proposal: %+v %v", got, err)
	}
	// The operator's own proposal is unaffected (it fails only because the
	// test daemon is not connected).
	if got, _ := s.ApproveProposal(ctx, opID); strings.Contains(got.Result, "revoked") {
		t.Fatalf("operator proposal refused: %+v", got)
	}
}

func TestCreator_RevokedTokenScheduleNotSent(t *testing.T) {
	ctx := context.Background()
	s, st, clk := scheduleServer(t, false)
	tctx := realToken(t, st, "planner")
	at := clk.now().Add(time.Hour)
	res := callToolAs(t, s, tctx, "schedule_message", map[string]any{"recipient": visibleJID, "message": "later", "send_at": at.Format(time.RFC3339)})
	id := scheduledID(t, res)
	if _, err := st.RevokeAPIToken(ctx, "planner"); err != nil {
		t.Fatal(err)
	}
	clk.set(at.Add(time.Second))
	if _, err := s.RunDueScheduled(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetProposal(ctx, id)
	if got.Status != store.OutboxFailed || !strings.Contains(got.Result, "revoked") {
		t.Fatalf("scheduled item of a revoked token: %+v", got)
	}
}

func TestCreator_OperatorScheduleIsMarked(t *testing.T) {
	s, _, clk := scheduleServer(t, false)
	p, err := s.ScheduleMessage(context.Background(), visibleJID, "wake up", clk.now().Add(time.Hour))
	if err != nil || p.CreatedBy != store.CreatorOperatorCLI {
		t.Fatalf("operator schedule: %+v %v", p, err)
	}
}
