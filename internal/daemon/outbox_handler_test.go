package daemon

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/store"
)

// fakeOutbox approves #1 (created by a client token) and fails the rest.
type fakeOutbox struct{}

func (fakeOutbox) ListProposals(context.Context, string) ([]store.Proposal, error) {
	return []store.Proposal{{ID: 1, Summary: "send_message → Alice", Status: store.OutboxPending, CreatedBy: "token:connector", ExpiresAt: time.Now().Add(time.Minute)}}, nil
}

func (fakeOutbox) ApproveProposal(_ context.Context, id int64) (store.Proposal, error) {
	if id != 1 {
		return store.Proposal{}, store.ErrProposalNotPending
	}
	return store.Proposal{ID: 1, Status: store.OutboxSent, CreatedBy: "token:connector"}, nil
}
func (fakeOutbox) RejectProposal(context.Context, int64) error { return nil }
func (fakeOutbox) CancelProposal(context.Context, int64) error { return nil }
func (fakeOutbox) ScheduleMessage(context.Context, string, string, time.Time) (store.Proposal, error) {
	return store.Proposal{}, errors.New("not used")
}

func TestOutbox_ApprovalAuditNamesCreator(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	base := startGuardedServer(t, Config{Access: st, Tokens: st, Audit: st, Outbox: fakeOutbox{}})

	if code, body := bearer(t, http.MethodPost, base+"/admin/outbox/1/approve", testToken, ""); code != http.StatusOK || !strings.Contains(body, `"created_by":"token:connector"`) {
		t.Fatalf("approve: %d %s", code, body)
	}
	entries, err := st.ListAudit(context.Background(), store.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Detail != "id=1 decision=approve creator=token:connector" {
		t.Fatalf("approval audit: %+v", entries)
	}
}
