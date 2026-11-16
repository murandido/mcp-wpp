package store

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"
)

// foldFixture opens a real store (through the crypto connector) with one
// allowed and one hidden chat, each holding accented and unaccented text.
func foldFixture(t *testing.T) (*Store, string, string) {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	const visible, hidden = "447700000001@s.whatsapp.net", "447700000002@s.whatsapp.net"
	_ = s.StoreChat(visible, "JOÃO Cauê", time.Now())
	_ = s.StoreChat(hidden, "João Secreto", time.Now())
	if err := s.SetChatAccess(ctx, visible, AccessAllowed, ""); err != nil {
		t.Fatal(err)
	}
	for _, m := range []Message{
		{ID: "v1", ChatJID: visible, Content: "Falei com o Cauê ontem"},
		{ID: "v2", ChatJID: visible, Content: "O caue chegou"},
		{ID: "v3", ChatJID: visible, Content: "JOÃO PAGOU 100% DO VALOR"},
		{ID: "v4", ChatJID: visible, Content: "nada a ver"},
		{ID: "h1", ChatJID: hidden, Content: "cauê no chat escondido"},
	} {
		m.Sender, m.Timestamp = m.ChatJID, time.Now()
		if err := s.StoreMessage(ctx, m, nil, nil, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	return s, visible, hidden
}

func ids(msgs []Message) string {
	var out []string
	for _, m := range msgs {
		out = append(out, m.ID)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// TestSearchFallback_AccentAndCaseInsensitive covers the LIKE path used
// without FTS5 (and for queries shorter than minFTSQuery).
func TestSearchFallback_AccentAndCaseInsensitive(t *testing.T) {
	s, _, _ := foldFixture(t)
	s.fts = false // force the fallback even where FTS5 exists
	ctx := context.Background()
	sc := s.Scoped()
	for q, want := range map[string]string{
		"cauê":  "v1,v2",
		"caue":  "v1,v2",
		"CAUÊ":  "v1,v2",
		"joão":  "v3",
		"JOAO":  "v3",
		"100%":  "v3", // a literal %, not a wildcard
		"0%d":   "",
		"pagou": "v3",
		"_":     "",
	} {
		msgs, err := sc.ListMessages(ctx, ListMessagesParams{Query: q, Limit: 50})
		if err != nil {
			t.Fatalf("search %q: %v", q, err)
		}
		if got := ids(msgs); got != want {
			t.Errorf("search %q = %q, want %q", q, got, want)
		}
	}
	// The unscoped store sees the hidden chat; the scoped view never does.
	if msgs, _ := s.ListMessages(ctx, ListMessagesParams{Query: "caue", Limit: 50}); ids(msgs) != "h1,v1,v2" {
		t.Errorf("unscoped search = %q", ids(msgs))
	}
}

func TestDigestKeywordsFallback_AccentInsensitive(t *testing.T) {
	s, _, _ := foldFixture(t)
	s.fts = false
	ctx := context.Background()
	d, err := s.Scoped().DigestWith(ctx, DigestParams{Since: time.Now().Add(-time.Hour), MaxPerGroup: 10, MaxGroups: 10, Keywords: []string{"CAUE"}})
	if err != nil {
		t.Fatal(err)
	}
	var got []Message
	for _, g := range d {
		got = append(got, g.Messages...)
	}
	if ids(got) != "v1,v2" {
		t.Errorf("digest keywords = %q, want v1,v2", ids(got))
	}
}

func TestChatAndContactSearch_AccentInsensitive(t *testing.T) {
	s, visible, _ := foldFixture(t)
	ctx := context.Background()
	sc := s.Scoped()
	chats, err := sc.ListChats(ctx, "joao caue", 10, 0, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(chats) != 1 || chats[0].JID != visible {
		t.Errorf("list chats = %+v", chats)
	}
	contacts, err := sc.SearchContacts(ctx, "JOAO")
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 1 || contacts[0].JID != visible {
		t.Errorf("search contacts = %+v", contacts)
	}
}

// TestFTS_AccentInsensitiveBothWays checks the FTS5 index folds accents in
// the query as well as in the text.
func TestFTS_AccentInsensitiveBothWays(t *testing.T) {
	s := openFTSStore(t)
	ctx := context.Background()
	const jid = "447700000001@s.whatsapp.net"
	_ = s.StoreChat(jid, "Alice", time.Now())
	for id, text := range map[string]string{"m1": "Falei com o Cauê", "m2": "o caue chegou", "m3": "JOÃO pagou"} {
		if err := s.StoreMessage(ctx, Message{ID: id, ChatJID: jid, Sender: jid, Content: text, Timestamp: time.Now()}, nil, nil, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	for q, want := range map[string]string{"cauê": "m1,m2", "CAUE": "m1,m2", "joão": "m3", "JOAO": "m3"} {
		msgs, err := s.ListMessages(ctx, ListMessagesParams{Query: q, Limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		if got := ids(msgs); got != want {
			t.Errorf("fts search %q = %q, want %q", q, got, want)
		}
	}
	var def string
	if err := s.db.QueryRow("SELECT sql FROM sqlite_master WHERE name = 'messages_fts'").Scan(&def); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(def, "remove_diacritics 2") {
		t.Errorf("index tokenizer does not remove diacritics: %s", def)
	}
}
