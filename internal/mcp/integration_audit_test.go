package mcp

import (
	"context"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/client"
	"github.com/murandido/mcp-wpp/internal/store"
)

// Send-policy decisions reach the audit log with the right outcome: a
// refusal (policy none, hidden chat) is "denied", a confirm-policy call is
// "proposed".
func TestAudit_RecordsSendPolicyOutcomes(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	_ = st.StoreChat(visibleJID, "Alice", time.Now())
	_ = st.SetChatAccess(ctx, visibleJID, store.AccessAllowed, "")
	c, err := client.New(ctx, client.Config{StoreDir: dir, Store: st, Logger: client.NewStderrLogger("test", "ERROR", false)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Disconnect)
	s, err := NewServerWithOptions(c, nil, Options{ConfirmSends: true, Audit: st, Tools: &ToolSelection{Enable: []string{"all"}}})
	if err != nil {
		t.Fatal(err)
	}

	send := func(to string) { callToolDirect(t, s, "send_message", map[string]any{"recipient": to, "message": "x"}) }
	send(visibleJID) // default confirm → proposed
	if err := st.SetChatSendPolicy(ctx, visibleJID, store.SendNone); err != nil {
		t.Fatal(err)
	}
	send(visibleJID) // none → denied
	send(hiddenJID)  // hidden → denied by the access middleware

	// Audit writes are detached from the call; give them a moment.
	var entries []store.AuditEntry
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		entries, err = st.ListAudit(ctx, store.AuditFilter{Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := map[string]int{}
	for _, e := range entries {
		if e.Action == "send_message" {
			got[e.Outcome]++
		}
	}
	if got["proposed"] != 1 || got["denied"] != 2 {
		t.Fatalf("send_message outcomes = %v, want 1 proposed and 2 denied (entries: %+v)", got, entries)
	}
}
