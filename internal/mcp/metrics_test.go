package mcp

import (
	"sync"
	"testing"
)

func TestObserveToolCalls(t *testing.T) {
	s, _ := accessServer(t)
	var mu sync.Mutex
	seen := map[string]int{}
	s.ObserveToolCalls(func(tool, outcome string) {
		mu.Lock()
		seen[tool+"/"+outcome]++
		mu.Unlock()
	})
	callToolDirect(t, s, "list_chats", map[string]any{})
	callToolDirect(t, s, "list_chats", map[string]any{})
	callToolDirect(t, s, "get_chat", map[string]any{"chat_jid": visibleJID})
	if res := callToolDirect(t, s, "get_chat", map[string]any{"chat_jid": hiddenJID}); !res.IsError {
		t.Fatal("hidden chat must be refused")
	}
	mu.Lock()
	defer mu.Unlock()
	if seen["list_chats/ok"] != 2 || seen["get_chat/ok"] != 1 {
		t.Fatalf("observed %v", seen)
	}
	// The refusal happens in the access middleware, before execution.
	if seen["get_chat/error"] != 0 {
		t.Fatalf("access refusals are not executions: %v", seen)
	}
}
