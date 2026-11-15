package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	waProto "go.mau.fi/whatsmeow/binary/proto"
	"go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"

	"github.com/murandido/mcp-wpp/internal/store"
	"github.com/murandido/mcp-wpp/internal/webhook"
)

func TestIncomingHookOnlyForLiveIncoming(t *testing.T) {
	c, _ := rsClient(t)
	var got []IncomingMessage
	c.OnIncomingMessage(func(m IncomingMessage) { got = append(got, m) })
	dm := types.NewJID("447700000001", types.DefaultUserServer)
	ts := time.Date(2026, 3, 5, 8, 0, 0, 0, time.UTC)

	c.handleMessage(liveMessage(dm, dm, "in-1", ts, false, &waProto.Message{ImageMessage: &waProto.ImageMessage{Caption: proto.String("look"), Mimetype: proto.String("image/jpeg")}}))
	c.handleMessage(liveMessage(dm, types.NewJID(historyOwnPhone, types.DefaultUserServer), "out-1", ts, true, text("mine")))
	c.handleMessage(liveMessage(types.StatusBroadcastJID, dm, "status-1", ts, false, text("story")))
	runHistorySync(c, rsDM, historyMsg(historyKey(rsDM, "hist-1", false, ""), text("old")))

	if len(got) != 1 {
		t.Fatalf("hook called %d times (%+v), want once for the live incoming message", len(got), got)
	}
	m := got[0]
	if m.ChatJID != rsDM || m.ChatName != "Alice" || m.ID != "in-1" || m.SenderJID != rsDM || m.SenderName != "Alice A." ||
		m.MediaType != "image" || m.Text != "look" || m.IsGroup || !m.Timestamp.Equal(ts) {
		t.Errorf("hook message = %+v", m)
	}
}

// TestWebhookEndToEnd drives live messages through the hook and a real
// dispatcher against an httptest endpoint: only the allowed chat is posted.
func TestWebhookEndToEnd(t *testing.T) {
	c, s := rsClient(t)
	ctx := context.Background()
	if err := s.SetChatAccess(ctx, rsDM, store.AccessAllowed, ""); err != nil {
		t.Fatal(err)
	}
	var (
		mu   sync.Mutex
		seen []webhook.Payload
	)
	done := make(chan struct{}, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var p webhook.Payload
		_ = json.NewDecoder(r.Body).Decode(&p)
		mu.Lock()
		seen = append(seen, p)
		mu.Unlock()
		done <- struct{}{}
	}))
	t.Cleanup(srv.Close)
	d, err := webhook.New(webhook.Config{URL: srv.URL, Secret: strings.Repeat("not-a-secret-", 2), Window: 20 * time.Millisecond},
		webhook.Options{Allowed: s.ChatAllowed, RedactJID: c.redactor.JID})
	if err != nil {
		t.Fatal(err)
	}
	c.OnIncomingMessage(func(m IncomingMessage) { d.Enqueue(webhook.Message(m)) })
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go d.Run(runCtx)

	ts := time.Now()
	dm := types.NewJID("447700000001", types.DefaultUserServer)
	group := types.NewJID("120363000000000001", types.GroupServer)
	c.handleMessage(liveMessage(group, dm, "hidden-1", ts, false, text("hidden group")))
	c.handleMessage(liveMessage(dm, dm, "dm-1", ts, false, text("visible")))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no webhook delivered")
	}
	time.Sleep(100 * time.Millisecond) // let a wrongly sent hidden batch arrive
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0].Chat.JID != rsDM || seen[0].Messages[0].ID != "dm-1" || seen[0].Messages[0].Text != "" {
		t.Fatalf("payloads = %+v, want only the allowed chat, without text", seen)
	}
}
