package store

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

var digestSince = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// digestStore allows Alice and the team group; Bob stays hidden.
func digestStore(t *testing.T) (*Store, *Store) {
	t.Helper()
	s := openAccessStore(t)
	ctx := context.Background()
	for _, j := range []string{aliceJID, teamJID} {
		if err := s.SetChatAccess(ctx, j, AccessAllowed, ""); err != nil {
			t.Fatal(err)
		}
	}
	return s, s.Scoped()
}

// summary renders a digest as "key:total[ids]" groups for comparisons.
func summary(d []ChatDigest) string {
	var parts []string
	for _, cd := range d {
		key := cd.Chat.JID
		if cd.Sender != "" {
			key = cd.Sender
		}
		var ids []string
		for _, m := range cd.Messages {
			ids = append(ids, m.ID)
		}
		parts = append(parts, key+":"+strconv.Itoa(cd.Total)+"["+strings.Join(ids, ",")+"]")
	}
	return strings.Join(parts, " ")
}

func digestOf(t *testing.T, s *Store, p DigestParams) string {
	t.Helper()
	if p.Since.IsZero() {
		p.Since = digestSince
	}
	d, err := s.DigestWith(context.Background(), p)
	if err != nil {
		t.Fatalf("DigestWith(%+v): %v", p, err)
	}
	out := summary(d)
	// Bob's direct chat is hidden: none of its messages may appear (Bob
	// may still appear as a sender in the allowed group).
	if p.GroupBy != DigestBySender && strings.Contains(out, bobJID+":") {
		t.Fatalf("hidden chat leaked into digest %+v: %s", p, out)
	}
	for _, hidden := range []string{"b1", "b2", "b3", "b9"} {
		if strings.Contains(out, hidden) {
			t.Fatalf("hidden chat leaked into digest %+v: %s", p, out)
		}
	}
	return out
}

func TestDigest_DefaultIsUnchanged(t *testing.T) {
	_, scoped := digestStore(t)
	got := digestOf(t, scoped, DigestParams{})
	want := teamJID + ":4[g1,g2,g3,g4] " + aliceJID + ":5[a1,a2,a3,a4,a5]"
	if got != want {
		t.Fatalf("digest = %s\nwant      %s", got, want)
	}
	old, err := scoped.Digest(context.Background(), digestSince, nil, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if summary(old) != teamJID+":4[g3,g4]" {
		t.Fatalf("Digest(max 2 per chat, 1 chat) = %s", summary(old))
	}
}

func TestDigest_OnlyUnread(t *testing.T) {
	s, scoped := digestStore(t)
	ctx := context.Background()
	if err := s.MarkChatReadThrough(ctx, aliceJID, []string{"a3"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	// Reading the hidden chat must not make it appear.
	if err := s.MarkChatReadThrough(ctx, bobJID, []string{"b1"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	got := digestOf(t, scoped, DigestParams{OnlyUnread: true})
	// Team has no read mark: every incoming message is unread. Alice: only
	// a5 is incoming and newer than a3 (a4 is ours).
	want := teamJID + ":3[g1,g3,g4] " + aliceJID + ":1[a5]"
	if got != want {
		t.Fatalf("unread digest = %s\nwant           %s", got, want)
	}
	if err := s.MarkChatReadThrough(ctx, teamJID, nil, time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if got := digestOf(t, scoped, DigestParams{OnlyUnread: true}); got != aliceJID+":1[a5]" {
		t.Fatalf("after reading the team chat: %s", got)
	}
}

func TestDigest_MentionsOnly(t *testing.T) {
	s, scoped := digestStore(t)
	ctx := context.Background()
	for _, m := range [][2]string{{"g3", teamJID}, {"b3", bobJID}} {
		if err := s.SetMentionsMe(ctx, m[0], m[1]); err != nil {
			t.Fatal(err)
		}
	}
	if got := digestOf(t, scoped, DigestParams{MentionsOnly: true}); got != teamJID+":1[g3]" {
		t.Fatalf("mentions digest = %s", got)
	}
}

func TestDigest_KeywordsLikeFallback(t *testing.T) {
	_, scoped := digestStore(t)
	if scoped.fts {
		t.Fatal("test store unexpectedly has FTS")
	}
	got := digestOf(t, scoped, DigestParams{Keywords: []string{"PIC", " kickoff ", "", "bob"}})
	want := aliceJID + ":1[a5] " + teamJID + ":1[g1]"
	if got != want {
		t.Fatalf("keyword digest = %s\nwant            %s", got, want)
	}
	// LIKE wildcards in a keyword are literal.
	if got := digestOf(t, scoped, DigestParams{Keywords: []string{"%"}}); got != "" {
		t.Fatalf("%% matched everything: %s", got)
	}
}

func TestDigest_KeywordsFTS(t *testing.T) {
	s, scoped := digestStore(t)
	ok, err := enableFTS(s.db)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Skip("this SQLite build lacks FTS5")
	}
	scoped.fts = true
	ctx := context.Background()
	if err := s.StoreMessage(ctx, Message{ID: "a6", ChatJID: aliceJID, Sender: aliceJID, Content: "A reunião é amanhã", Timestamp: time.Date(2026, 1, 11, 9, 0, 0, 0, time.UTC)}, nil, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.StoreMessage(ctx, Message{ID: "b9", ChatJID: bobJID, Sender: bobJID, Content: "reuniao secreta", Timestamp: time.Date(2026, 1, 11, 9, 0, 0, 0, time.UTC)}, nil, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	// "REUNIAO" goes through the index (accent-insensitive), "ki" is too
	// short for it and uses a substring match ("team kickoff").
	if got := digestOf(t, scoped, DigestParams{Keywords: []string{"REUNIAO", "ki"}}); got != aliceJID+":1[a6] "+teamJID+":1[g1]" {
		t.Fatalf("FTS keyword digest = %s", got)
	}
	if strings.Contains(digestOf(t, scoped, DigestParams{Keywords: []string{"secreta"}}), "b9") {
		t.Fatal("hidden chat matched by FTS")
	}
}

func TestDigest_GroupBySender(t *testing.T) {
	_, scoped := digestStore(t)
	got := digestOf(t, scoped, DigestParams{GroupBy: DigestBySender})
	// Bob appears as a sender in the allowed group, never with his hidden
	// direct chat's messages.
	want := "447700000002@s.whatsapp.net:2[g3,g4] 447700000001@s.whatsapp.net:4[a1,a3,g1,a5] me:3[a2,a4,g2]"
	if got != want {
		t.Fatalf("by-sender digest = %s\nwant              %s", got, want)
	}
	d, _ := scoped.DigestWith(context.Background(), DigestParams{Since: digestSince, GroupBy: DigestBySender})
	text := scoped.FormatDigest(context.Background(), d, digestSince)
	if !strings.Contains(text, "from 3 sender(s)") || !strings.Contains(text, "## Me (me): 3 new") || !strings.Contains(text, "Chat: Project Team") {
		t.Fatalf("formatted by-sender digest:\n%s", text)
	}
}

func TestDigest_Combined(t *testing.T) {
	s, scoped := digestStore(t)
	ctx := context.Background()
	_ = s.MarkChatReadThrough(ctx, teamJID, []string{"g1"}, time.Time{})
	_ = s.SetMentionsMe(ctx, "g4", teamJID)
	_ = s.SetMentionsMe(ctx, "a5", aliceJID)
	got := digestOf(t, scoped, DigestParams{OnlyUnread: true, MentionsOnly: true, Keywords: []string{"here"}, GroupBy: DigestBySender})
	if got != "447700000002@s.whatsapp.net:1[g4]" {
		t.Fatalf("combined digest = %s", got)
	}
	got = digestOf(t, scoped, DigestParams{OnlyUnread: true, ChatJIDs: []string{aliceJID, bobJID}})
	if got != aliceJID+":3[a1,a3,a5]" {
		t.Fatalf("unread digest restricted to chats = %s", got)
	}
	if got := digestOf(t, scoped, DigestParams{ChatJIDs: []string{bobJID}}); got != "" {
		t.Fatalf("asking for the hidden chat returned %s", got)
	}
}

func TestDigest_BadGroupBy(t *testing.T) {
	_, scoped := digestStore(t)
	if _, err := scoped.DigestWith(context.Background(), DigestParams{Since: digestSince, GroupBy: "day"}); err == nil {
		t.Fatal("accepted group_by=day")
	}
}

func TestDigestSchemaMigration(t *testing.T) {
	s := openTestStore(t)
	// Rows cached before the migration (the seed predates the column) are
	// not mentions; a second run is a no-op.
	var n int
	if err := s.db.QueryRow("SELECT count(*) FROM messages WHERE mentions_me").Scan(&n); err != nil || n != 0 {
		t.Fatalf("mentions after migration = %d, %v", n, err)
	}
	if err := applyDigestSchema(s.db); err != nil {
		t.Fatalf("second migration: %v", err)
	}
}

func TestMarkChatReadThrough(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if _, ok, _ := s.ChatLastRead(ctx, aliceJID); ok {
		t.Fatal("read mark before any read")
	}
	// Nothing cached and no fallback: nothing recorded.
	if err := s.MarkChatReadThrough(ctx, aliceJID, []string{"nope"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.ChatLastRead(ctx, aliceJID); ok {
		t.Fatal("read mark without a known time")
	}
	_ = s.MarkChatReadThrough(ctx, aliceJID, []string{"a1", "a3"}, time.Time{})
	at, ok, _ := s.ChatLastRead(ctx, aliceJID)
	if !ok || !at.Equal(time.Date(2026, 1, 3, 9, 10, 0, 0, time.UTC)) {
		t.Fatalf("read mark = %v", at)
	}
	_ = s.MarkChatReadThrough(ctx, aliceJID, []string{"a1"}, time.Time{})
	if at2, _, _ := s.ChatLastRead(ctx, aliceJID); !at2.Equal(at) {
		t.Fatalf("read mark moved back to %v", at2)
	}
}

func TestRewindChatRead(t *testing.T) {
	s, scoped := digestStore(t)
	ctx := context.Background()
	_ = s.MarkChatReadThrough(ctx, aliceJID, []string{"a5"}, time.Time{})
	_ = s.MarkChatReadThrough(ctx, teamJID, nil, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	if got := digestOf(t, scoped, DigestParams{OnlyUnread: true}); got != "" {
		t.Fatalf("everything read, digest = %s", got)
	}

	// Back to a3: a3 and later incoming messages are unread again.
	if err := s.RewindChatRead(ctx, aliceJID, "a3"); err != nil {
		t.Fatal(err)
	}
	if got := digestOf(t, scoped, DigestParams{OnlyUnread: true}); got != aliceJID+":2[a3,a5]" {
		t.Fatalf("after rewinding to a3: %s", got)
	}
	// Never forward: rewinding "to" a5 keeps a3 unread.
	if err := s.RewindChatRead(ctx, aliceJID, "a5"); err != nil {
		t.Fatal(err)
	}
	if got := digestOf(t, scoped, DigestParams{OnlyUnread: true}); got != aliceJID+":2[a3,a5]" {
		t.Fatalf("rewind moved the mark forward: %s", got)
	}
	// Without a message: the whole chat is unread.
	if err := s.RewindChatRead(ctx, teamJID, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.ChatLastRead(ctx, teamJID); ok {
		t.Fatal("read mark not cleared")
	}
	if got := digestOf(t, scoped, DigestParams{OnlyUnread: true}); got != teamJID+":3[g1,g3,g4] "+aliceJID+":2[a3,a5]" {
		t.Fatalf("after clearing the team mark: %s", got)
	}
	// A message from another chat is not found.
	if err := s.RewindChatRead(ctx, aliceJID, "g1"); err != ErrMessageNotFound {
		t.Fatalf("message from another chat: %v", err)
	}
	if err := s.RewindChatRead(ctx, "", ""); err == nil {
		t.Fatal("empty chat accepted")
	}
}
