package mcp

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/client"
	"github.com/murandido/mcp-wpp/internal/store"
)

const ownJID = "447700000009@s.whatsapp.net"

// selfServer is a confirming write server with auditing and self-approval
// on, whose own chat is ownJID (allowed, so only the self-approve guard can
// refuse it).
func selfServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	s, st := tokenServer(t, Options{ConfirmSends: true})
	s.EnableSelfApprove()
	s.ownChats = func() []string { return []string{ownJID, "112233445566@lid"} }
	ctx := context.Background()
	_ = st.StoreChat(ownJID, "Me", nowUTC())
	_ = st.SetChatAccess(ctx, ownJID, store.AccessAllowed, "")
	return s, st
}

func selfAudit(t *testing.T, st *store.Store) []store.AuditEntry {
	t.Helper()
	all, err := st.ListAudit(context.Background(), store.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var out []store.AuditEntry
	for _, e := range all {
		if e.Actor == SelfApproveActor {
			out = append(out, e)
		}
	}
	return out
}

func TestSelfApprove_ApproveRejectAndList(t *testing.T) {
	ctx := context.Background()
	s, st := selfServer(t)
	a := proposalID(t, callToolDirect(t, s, "send_message", map[string]any{"recipient": visibleJID, "message": "secret text"}))
	b := proposalID(t, callToolDirect(t, s, "send_message", map[string]any{"recipient": visibleJID, "message": "other"}))

	list := s.HandleSelfCommand(ctx, client.SelfCommand{Text: "Outbox"})
	if !strings.Contains(list, "2 awaiting approval") || !strings.Contains(list, "by operator") {
		t.Fatalf("outbox reply: %q", list)
	}

	// approve runs the same path as `wpp-mcp outbox approve`: claimed once,
	// executed (and failing here: the test daemon is unpaired).
	reply := s.HandleSelfCommand(ctx, client.SelfCommand{Text: "approve #" + itoa(a)})
	if !strings.HasPrefix(reply, "#"+itoa(a)+": failed") || !strings.Contains(reply, "Not connected") {
		t.Fatalf("approve reply: %q", reply)
	}
	if p, _ := st.GetProposal(ctx, a); p.Status != store.OutboxFailed {
		t.Fatalf("approved proposal: %+v", p)
	}
	if reply := s.HandleSelfCommand(ctx, client.SelfCommand{Text: "approve " + itoa(a)}); !strings.Contains(reply, "not pending") {
		t.Fatalf("second approval: %q", reply)
	}
	if reply := s.HandleSelfCommand(ctx, client.SelfCommand{Text: "reject " + itoa(b)}); reply != "#"+itoa(b)+": rejected" {
		t.Fatalf("reject reply: %q", reply)
	}

	entries := selfAudit(t, st)
	if len(entries) != 4 {
		t.Fatalf("self-chat audit: %+v", entries)
	}
	for _, e := range entries {
		if strings.Contains(e.Detail, "secret") || e.Kind != store.AuditAdmin || !strings.HasPrefix(e.Action, "selfchat ") {
			t.Errorf("audit entry: %+v", e)
		}
	}
	if e := entries[0]; e.Action != "selfchat reject" || e.Detail != "id="+itoa(b)+" creator=operator" || e.Outcome != store.OutcomeOK {
		t.Errorf("reject entry: %+v", e)
	}
}

func TestSelfApprove_RejectedAndNonCommands(t *testing.T) {
	ctx := context.Background()
	s, st := selfServer(t)
	id := proposalID(t, callToolDirect(t, s, "send_message", map[string]any{"recipient": visibleJID, "message": "x"}))

	for _, rejected := range []string{client.SelfRejectOwnDevice, client.SelfRejectTooOld} {
		if reply := s.HandleSelfCommand(ctx, client.SelfCommand{Text: "approve " + itoa(id), Rejected: rejected}); reply != "" {
			t.Fatalf("%s: replied %q", rejected, reply)
		}
	}
	if p, _ := st.GetProposal(ctx, id); p.Status != store.OutboxPending {
		t.Fatalf("a rejected command acted: %+v", p)
	}
	for _, note := range []string{"buy milk", "approve", "approve me", "approve 3 now", "reject -1", "outbox please"} {
		if reply := s.HandleSelfCommand(ctx, client.SelfCommand{Text: note}); reply != "" {
			t.Fatalf("note %q answered %q", note, reply)
		}
	}
	entries := selfAudit(t, st)
	if len(entries) != 2 || entries[0].Outcome != store.OutcomeDenied || entries[1].Outcome != store.OutcomeDenied || !strings.Contains(entries[1].Detail, "rejected=own_device") {
		t.Fatalf("rejected commands must be audited as denied, notes not at all: %+v", entries)
	}

	// Off: nothing is handled.
	s.selfApprove = false
	if reply := s.HandleSelfCommand(ctx, client.SelfCommand{Text: "outbox"}); reply != "" {
		t.Fatalf("self-approve off still answers: %q", reply)
	}
}

func TestSelfApprove_OwnChatClosedToMCP(t *testing.T) {
	ctx := context.Background()
	s, _ := selfServer(t)
	for _, ref := range []string{ownJID, "447700000009"} {
		res := callToolDirect(t, s, "send_message", map[string]any{"recipient": ref, "message": "approve 1"})
		if !res.IsError || !strings.Contains(res.Text, "own chat") {
			t.Fatalf("%s: %+v", ref, res)
		}
	}
	// A proposal for the own chat made before the flag was on is refused at
	// approval as well.
	s.selfApprove = false
	id := proposalID(t, callToolDirect(t, s, "send_message", map[string]any{"recipient": ownJID, "message": "approve 1"}))
	s.selfApprove = true
	if p, _ := s.ApproveProposal(ctx, id); p.Status != store.OutboxFailed || !strings.Contains(p.Result, "own chat") {
		t.Fatalf("approval to the own chat: %+v", p)
	}
	// Reads are unaffected, and other chats still work.
	if res := callToolDirect(t, s, "send_message", map[string]any{"recipient": visibleJID, "message": "hi"}); !isProposal(res) {
		t.Fatalf("other chat: %+v", res)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func nowUTC() time.Time { return time.Now().UTC() }
