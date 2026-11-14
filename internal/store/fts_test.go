package store

import (
	"context"
	"os"
	"testing"
	"time"
)

func openFTSStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if !s.fts {
		if os.Getenv("WPP_MCP_REQUIRE_CIPHER") == "1" {
			t.Fatal("FTS5 is required but this build lacks it")
		}
		t.Skip("FTS5 not compiled in; run through `make test`")
	}
	return s
}

func TestFTS_AccentInsensitivePrefixSearch(t *testing.T) {
	s := openFTSStore(t)
	ctx := context.Background()
	const jid = "447700000001@s.whatsapp.net"
	if err := s.StoreChat(jid, "Alice", time.Now()); err != nil {
		t.Fatal(err)
	}
	for id, text := range map[string]string{
		"m1": "Não sei, amanhã eu vejo",
		"m2": "Reunião às 10h na sala grande",
		"m3": "nothing relevant",
	} {
		if err := s.StoreMessage(ctx, Message{ID: id, ChatJID: jid, Sender: jid, Content: text, Timestamp: time.Now()}, nil, nil, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	search := func(q string) []string {
		t.Helper()
		msgs, err := s.ListMessages(ctx, ListMessagesParams{Query: q, Limit: 50})
		if err != nil {
			t.Fatalf("search %q: %v", q, err)
		}
		var ids []string
		for _, m := range msgs {
			ids = append(ids, m.ID)
		}
		return ids
	}
	for q, want := range map[string]string{
		"nao":           "m1",
		"AMANHA vejo":   "m1",
		"reuni sala":    "m2",
		`"reuniao"`:     "m2", // quotes are stripped, never a syntax error
		`reuniao OR`:    "",   // operators are words like any other: "or" must appear
		"sala grande x": "",
	} {
		got := search(q)
		if want == "" && len(got) != 0 || want != "" && (len(got) != 1 || got[0] != want) {
			t.Errorf("search %q = %v, want %q", q, got, want)
		}
	}

	// Edits are re-indexed.
	if _, err := s.ApplyEdit(ctx, jid, "m3", Author{Senders: []string{jid}}, "orçamento aprovado", time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := search("orcamento"); len(got) != 1 || got[0] != "m3" {
		t.Errorf("edited message not re-indexed: %v", got)
	}
	if got := search("relevant"); len(got) != 0 {
		t.Errorf("old text still indexed after edit: %v", got)
	}
}

func TestFTS_BackfillsExistingMessages(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !s.fts {
		s.Close()
		t.Skip("FTS5 not compiled in")
	}
	const jid = "447700000001@s.whatsapp.net"
	_ = s.StoreChat(jid, "Alice", time.Now())
	_ = s.StoreMessage(context.Background(), Message{ID: "old", ChatJID: jid, Sender: jid, Content: "mensagem antiga", Timestamp: time.Now()}, nil, nil, nil, 0)
	// Simulate a store created before the index existed.
	if _, err := s.db.Exec("DROP TABLE messages_fts; DROP TRIGGER messages_fts_ai; DROP TRIGGER messages_fts_ad; DROP TRIGGER messages_fts_au"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	msgs, err := s.ListMessages(context.Background(), ListMessagesParams{Query: "antiga", Limit: 10})
	if err != nil || len(msgs) != 1 {
		t.Fatalf("backfill: %d %v", len(msgs), err)
	}
}
