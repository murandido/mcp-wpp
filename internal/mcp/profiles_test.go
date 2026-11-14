package mcp

import (
	"slices"
	"testing"
)

func TestEveryToolHasGroup(t *testing.T) {
	tools := NewServer(nil, nil, true).MCP().ListTools()
	for name := range tools {
		if toolGroup[name] == "" && !accessTools[name] {
			t.Errorf("tool %q has no group in profiles.go", name)
		}
	}
	for name := range toolGroup {
		if tools[name] == nil {
			t.Errorf("profiles.go names unregistered tool %q", name)
		}
	}
}

func names(t *testing.T, opts Options) []string {
	t.Helper()
	s, err := NewServerWithOptions(nil, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	return s.ToolNames()
}

func TestDefaultProfile_ReadOnlyHidesOptInGroups(t *testing.T) {
	got := names(t, Options{ReadOnly: true, Tools: &ToolSelection{}})
	for _, hidden := range []string{"send_message", "list_groups", "get_blocklist", "is_on_whatsapp", "send_poll", "transcribe_audio"} {
		if slices.Contains(got, hidden) {
			t.Errorf("default read-only profile exposes %q", hidden)
		}
	}
	for _, want := range []string{"list_chats", "list_messages", "get_message_context", "download_media"} {
		if !slices.Contains(got, want) {
			t.Errorf("default read-only profile hides %q", want)
		}
	}
}

func TestDefaultProfile_WriteAddsMessagingOnly(t *testing.T) {
	got := names(t, Options{Tools: &ToolSelection{}})
	if !slices.Contains(got, "send_message") {
		t.Error("write mode default profile should expose send_message")
	}
	if slices.Contains(got, "create_group") || slices.Contains(got, "set_privacy_setting") {
		t.Error("write mode default profile exposes opt-in groups")
	}
}

func TestToolSelection_EnableAndDisable(t *testing.T) {
	got := names(t, Options{Tools: &ToolSelection{Enable: []string{"core", "groups"}, Disable: []string{"leave_group"}}})
	if !slices.Contains(got, "list_groups") || slices.Contains(got, "leave_group") || slices.Contains(got, "send_message") {
		t.Fatalf("unexpected selection: %v", got)
	}
	// Read-only still wins over an explicit enable.
	got = names(t, Options{ReadOnly: true, Tools: &ToolSelection{Enable: []string{"all"}}})
	if slices.Contains(got, "send_message") {
		t.Fatal("read-only mode exposed send_message")
	}
}

func TestToolSelection_UnknownNameFails(t *testing.T) {
	if _, err := NewServerWithOptions(nil, nil, Options{Tools: &ToolSelection{Enable: []string{"core", "sendmessage"}}}); err == nil {
		t.Fatal("typo in -tools must be an error")
	}
	if _, err := NewServerWithOptions(nil, nil, Options{Tools: &ToolSelection{Disable: []string{"nope"}}}); err == nil {
		t.Fatal("typo in -disable-tools must be an error")
	}
}
