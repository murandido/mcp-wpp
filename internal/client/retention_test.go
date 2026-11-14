package client

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/store"
)

func TestPurgeOlderThan(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	const jid = "447700000099@s.whatsapp.net"
	_ = s.StoreChat(jid, "test", time.Now())
	_ = s.SetChatAccess(ctx, jid, store.AccessAllowed, "")
	old, fresh := time.Now().Add(-40*24*time.Hour), time.Now()
	for id, ts := range map[string]time.Time{"OLD": old, "NEW": fresh} {
		if err := s.StoreMessage(ctx, store.Message{ID: id, ChatJID: jid, Sender: jid, Content: id, Timestamp: ts}, nil, nil, nil, 0); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(s.Dir(), jid, hex.EncodeToString([]byte(id)))
		_ = os.MkdirAll(dir, 0o700)
		_ = os.WriteFile(filepath.Join(dir, "f.bin"), []byte("x"), 0o600)
	}
	if err := s.PutTranscript(ctx, store.Transcript{MessageID: "OLD", ChatJID: jid, Text: "old words"}); err != nil {
		t.Fatal(err)
	}

	c := newClientWithStore(t, s)
	n, err := c.PurgeOlderThan(ctx, 30*24*time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("purged %d: %v", n, err)
	}
	msgs, _ := s.ListMessages(ctx, store.ListMessagesParams{ChatJID: jid, Limit: 10})
	if len(msgs) != 1 || msgs[0].ID != "NEW" {
		t.Fatalf("remaining messages: %+v", msgs)
	}
	if tr, _ := s.GetTranscript(ctx, "OLD", jid); tr != nil {
		t.Fatal("transcript of a purged message survived")
	}
	if _, err := os.Stat(filepath.Join(s.Dir(), jid, hex.EncodeToString([]byte("OLD")))); !os.IsNotExist(err) {
		t.Fatal("media of a purged message survived")
	}
	if _, err := os.Stat(filepath.Join(s.Dir(), jid, hex.EncodeToString([]byte("NEW")))); err != nil {
		t.Fatal("media of a fresh message was removed")
	}
	if ok, _ := s.ChatAllowed(ctx, jid); !ok {
		t.Fatal("retention must not drop access decisions")
	}
}
