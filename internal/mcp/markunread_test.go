package mcp

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestMarkUnread_RewindsVisibleChatOnly(t *testing.T) {
	s, st := accessServer(t)
	ctx := context.Background()
	future := time.Now().Add(time.Hour)
	for _, jid := range []string{visibleJID, hiddenJID} {
		if err := st.MarkChatReadThrough(ctx, jid, nil, future); err != nil {
			t.Fatal(err)
		}
	}

	res := callToolDirect(t, s, "mark_unread", map[string]any{"chat_jid": visibleJID, "message_id": "msg-visible"})
	if res.IsError || !strings.Contains(res.Text, "local digest read state only") {
		t.Fatalf("mark_unread: %+v", res)
	}
	at, ok, _ := st.ChatLastRead(ctx, visibleJID)
	if !ok || !at.Before(time.Now()) {
		t.Fatalf("read mark not rewound: %v %v", at, ok)
	}
	if res := callToolDirect(t, s, "digest", map[string]any{"only_unread": true, "hours": 1}); !strings.Contains(res.Text, "hello from Alice") {
		t.Fatalf("rewound message missing from the unread digest: %s", res.Text)
	}

	res = callToolDirect(t, s, "mark_unread", map[string]any{"chat_jid": visibleJID, "message_id": "msg-hidden"})
	if !res.IsError || !strings.Contains(res.Text, "message not found") {
		t.Fatalf("message from another chat: %+v", res)
	}

	// Hidden chat: "chat not found", and its read mark is untouched.
	res = callToolDirect(t, s, "mark_unread", map[string]any{"chat_jid": hiddenJID})
	if !res.IsError || !strings.Contains(res.Text, "chat not found") {
		t.Fatalf("hidden chat: %+v", res)
	}
	if at, ok, _ := st.ChatLastRead(ctx, hiddenJID); !ok || at.Unix() != future.Unix() {
		t.Fatalf("hidden chat's read mark changed: %v %v", at, ok)
	}

	// Without a message the whole chat becomes unread.
	if res := callToolDirect(t, s, "mark_unread", map[string]any{"chat_jid": visibleJID}); res.IsError {
		t.Fatalf("whole chat: %+v", res)
	}
	if _, ok, _ := st.ChatLastRead(ctx, visibleJID); ok {
		t.Fatal("read mark not cleared")
	}
}
