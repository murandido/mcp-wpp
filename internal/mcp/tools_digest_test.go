package mcp

import (
	"context"
	"strings"
	"testing"
)

func TestDigestFiltersNeverShowHiddenChats(t *testing.T) {
	s, st := accessServer(t)
	ctx := context.Background()
	if err := st.SetMentionsMe(ctx, "msg-hidden", hiddenJID); err != nil {
		t.Fatal(err)
	}
	if err := st.SetMentionsMe(ctx, "msg-visible", visibleJID); err != nil {
		t.Fatal(err)
	}
	for _, args := range []map[string]any{
		{"only_unread": true},
		{"mentions_only": true},
		{"keywords": []string{"hello"}},
		{"keywords": []string{"secret"}, "chat_jids": []string{hiddenJID}},
		{"group_by": "sender"},
		{"group_by": "sender", "only_unread": true, "mentions_only": true, "keywords": []string{"HELLO", "zz"}},
	} {
		res := callToolDirect(t, s, "digest", args)
		if res.IsError {
			t.Fatalf("digest %v: %s", args, res.Text)
		}
		if strings.Contains(res.Text, "Bob") || strings.Contains(res.Text, hiddenJID) || strings.Contains(res.Text, "msg-hidden") {
			t.Fatalf("digest %v leaks the hidden chat: %s", args, res.Text)
		}
	}
	res := callToolDirect(t, s, "digest", map[string]any{"mentions_only": true, "group_by": "sender"})
	if !strings.Contains(res.Text, "hello from Alice") || !strings.Contains(res.Text, "sender(s)") {
		t.Fatalf("mentions by sender misses the allowed chat: %s", res.Text)
	}
	if res := callToolDirect(t, s, "digest", map[string]any{"keywords": []string{"nothing-matches"}}); !strings.Contains(res.Text, "No messages") {
		t.Fatalf("unmatched keyword: %s", res.Text)
	}
	if res := callToolDirect(t, s, "digest", map[string]any{"group_by": "day"}); !res.IsError {
		t.Fatalf("group_by=day accepted: %s", res.Text)
	}
}
